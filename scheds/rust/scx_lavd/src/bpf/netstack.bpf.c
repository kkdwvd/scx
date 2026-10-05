// SPDX-License-Identifier: GPL-2.0
/*
 * The network soft partition.
 *
 * A network stack, in the kernel (the BPF NAPI pollers) or in user space,
 * asks the scheduler for CPUs instead of being pinned to a static set: it
 * sets a target count, lavd grants CPUs within the host's cap and the
 * stack's candidates, keeps ordinary tasks off them, steers the stack's
 * registered threads onto them with priority, and takes the CPUs back when
 * the stack lowers its target.
 *
 * The request and the grant share one record, netstack_shm. The stack
 * writes the request; lavd's sys_stat tick reads it and answers. The tick
 * is the only writer of the partition and of the active and overflow masks,
 * so a request cannot race the mask rebuilds of core compaction, and a grant
 * takes effect within one tick (LAVD_SYS_STAT_INTERVAL_NS).
 *
 * A granted CPU is marked in its cpu_ctx (NETSTACK_CPU_GRANTED) and in
 * netstack_cpumask; netstack_free_cpumask holds the online CPUs outside the
 * partition for the paths that need the complement. Registered threads are
 * marked in their task_ctx and dispatched from a per-CPU net DSQ; foreign
 * pinned tasks keep running from the per-CPU DSQ.
 */
#include <scx/common.bpf.h>
#include <bpf_arena_common.bpf.h>
#include "intf.h"
#include "lavd.bpf.h"
#include "util.bpf.h"
#include "power.bpf.h"
#include <errno.h>
#include <stdbool.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Options
 */
const volatile bool	netstack_enabled;
const volatile u32	netstack_max_cpus;	/* the host's cap on the partition */
const volatile u32	netstack_min_cpus;
const volatile u64	netstack_slice_ns;	/* a registered thread's slice on a partition CPU */

/*
 * The granted CPUs, their complement among the online CPUs, and the
 * candidates of the request being applied.
 */
private(LAVD) struct bpf_cpumask __kptr *netstack_cpumask;
private(LAVD) struct bpf_cpumask __kptr *netstack_free_cpumask;
private(LAVD) struct bpf_cpumask __kptr *netstack_cand_cpumask;

/*
 * The shared record. One entry, mmapable so that a user space stack can
 * read the grant without a system call.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct netstack_shm);
	__uint(map_flags, BPF_F_MMAPABLE);
} netstack_shm SEC(".maps");

/* The tick's snapshot of the request masks, taken under the seqlock. */
static u64		req_candidates[NETSTACK_MASK_WORDS];
static u64		req_drop[NETSTACK_MASK_WORDS];
static u64		last_nr_cpus_onln;
/*
 * The grant being built, in memory rather than a register: a counter
 * carried across the loops in a register, compared against the target at
 * each step, keeps the verifier from converging the loop's states.
 */
static u32		resize_nr;

static __always_inline struct netstack_shm *netstack_rec(void)
{
	u32 zero = 0;

	return bpf_map_lookup_elem(&netstack_shm, &zero);
}

static __always_inline bool mask_test(const u64 *mask, u32 cpu)
{
	if (cpu >= NETSTACK_CPU_ID_MAX)
		return false;
	return mask[cpu / 64] & (1ULL << (cpu % 64));
}

/*
 * Register or unregister @p as a network thread. Registration is a field of
 * its own in the task context rather than a flag bit: the scheduler's flag
 * updates are read-modify-writes under the task's rq lock, which a writer
 * from another context would race.
 */
__hidden
int netstack_register_task(struct task_struct *p, bool on)
{
	struct netstack_shm *s = netstack_rec();
	task_ctx *taskc;

	if (!netstack_enabled || !s)
		return -ENODEV;
	taskc = find_task_ctx(p);
	if (!taskc)
		return -ESRCH;
	if (!!READ_ONCE(taskc->netstack) == on)
		return 0;
	WRITE_ONCE(taskc->netstack, on);
	if (on)
		__sync_fetch_and_add(&s->nr_registered, 1);
	else
		__sync_fetch_and_sub(&s->nr_registered, 1);
	return 0;
}

/* A registered thread exits: it leaves the count. */
__hidden
void netstack_task_exit(task_ctx *taskc)
{
	struct netstack_shm *s = netstack_rec();

	if (!taskc->netstack || !s)
		return;
	taskc->netstack = 0;
	__sync_fetch_and_sub(&s->nr_registered, 1);
}

/*
 * Choose the grant for a request and apply it: keep the granted candidates
 * the stack did not drop, most preferred first in lavd's CPU order; add free
 * candidates in that order, whole cores under SMT; release the rest. A CPU
 * that joins leaves the active and overflow sets and is kicked so that its
 * running task is preempted; the first dispatch on it then re-enqueues
 * whatever its local DSQ still holds. A CPU that leaves goes back to the
 * active set; core compaction places it on its next pass.
 */
static __noinline int netstack_resize(struct netstack_shm *s, u32 target, u32 flags)
{
	struct bpf_cpumask *net, *free, *cand, *active, *ovrflw;
	const volatile u16 *cpu_order = get_cpu_order();
	const struct cpumask *online;
	struct cpu_ctx *cpuc;
	u32 cap, want, cpu;
	int i, words;

	resize_nr = 0;
	bpf_rcu_read_lock();
	net = netstack_cpumask;
	free = netstack_free_cpumask;
	cand = netstack_cand_cpumask;
	active = active_cpumask;
	ovrflw = ovrflw_cpumask;
	if (!net || !free || !cand || !active || !ovrflw) {
		bpf_rcu_read_unlock();
		return -ENOMEM;
	}

	/* The host's cap: the operator's, and one CPU at least for the rest. */
	cap = netstack_max_cpus;
	if (nr_cpus_onln && cap > nr_cpus_onln - 1)
		cap = nr_cpus_onln - 1;
	want = target;
	if (want < netstack_min_cpus)
		want = netstack_min_cpus;
	if (want > cap) {
		s->nr_denied += want - cap;
		want = cap;
	}

	/* The candidates: what the stack offered, or every CPU, online only. */
	online = scx_bpf_get_online_cpumask();
	if (flags & NETSTACK_REQ_CANDIDATES) {
		bpf_cpumask_clear(cand);
		bpf_for(i, 0, nr_cpu_ids) {
			if (i >= LAVD_CPU_ID_MAX)
				break;
			if (mask_test(req_candidates, i) &&
			    bpf_cpumask_test_cpu(i, online))
				bpf_cpumask_set_cpu(i, cand);
		}
	} else {
		bpf_cpumask_copy(cand, online);
	}
	scx_bpf_put_cpumask(online);

	/* Pass 1: keep granted candidates the stack did not drop. */
	bpf_for(i, 0, nr_cpu_ids) {
		if (i >= LAVD_CPU_ID_MAX)
			break;
		cpu = cpu_order[i];
		if (cpu >= LAVD_CPU_ID_MAX)
			break;
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc)
			break;
		cpuc->netstack &= ~NETSTACK_CPU_NEXT;
		if (!(cpuc->netstack & NETSTACK_CPU_GRANTED) || !cpuc->is_online)
			continue;
		if (resize_nr >= want || !bpf_cpumask_test_cpu(cpu, cast_mask(cand)) ||
		    ((flags & NETSTACK_REQ_DROP) && mask_test(req_drop, cpu)))
			continue;
		cpuc->netstack |= NETSTACK_CPU_NEXT;
		resize_nr++;
	}

	/* Pass 2: add free candidates in preference order, whole cores under SMT. */
	bpf_for(i, 0, nr_cpu_ids) {
		if (resize_nr >= want || i >= LAVD_CPU_ID_MAX)
			break;
		cpu = cpu_order[i];
		if (cpu >= LAVD_CPU_ID_MAX)
			break;
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc)
			break;
		if ((cpuc->netstack & NETSTACK_CPU_NEXT) || !cpuc->is_online ||
		    !bpf_cpumask_test_cpu(cpu, cast_mask(cand)))
			continue;
		cpuc->netstack |= NETSTACK_CPU_NEXT;
		resize_nr++;
		if (is_smt_active && resize_nr < want) {
			const volatile u32 *sibling = MEMBER_VPTR(cpu_sibling, [cpu]);
			struct cpu_ctx *sibc;

			if (!sibling || *sibling == cpu || *sibling >= LAVD_CPU_ID_MAX)
				continue;
			sibc = get_cpu_ctx_id(*sibling);
			if (!sibc || (sibc->netstack & NETSTACK_CPU_NEXT) ||
			    !sibc->is_online ||
			    !bpf_cpumask_test_cpu(*sibling, cast_mask(cand)))
				continue;
			sibc->netstack |= NETSTACK_CPU_NEXT;
			resize_nr++;
		}
	}

	/* Pass 3: apply the transitions and publish the grant mask. */
	words = (nr_cpu_ids + 63) / 64;
	bpf_for(i, 0, words) {
		if (i >= NETSTACK_MASK_WORDS)
			break;
		s->granted[i] = 0;
	}
	bpf_for(cpu, 0, nr_cpu_ids) {
		bool was, now;

		if (cpu >= LAVD_CPU_ID_MAX)
			break;
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc)
			break;
		was = cpuc->netstack & NETSTACK_CPU_GRANTED;
		now = cpuc->netstack & NETSTACK_CPU_NEXT;
		if (now) {
			s->granted[cpu / 64] |= 1ULL << (cpu % 64);
			if (was) {
				cpuc->netstack &= ~NETSTACK_CPU_NEXT;
				continue;
			}
			cpuc->netstack = NETSTACK_CPU_GRANTED | NETSTACK_CPU_FRESH;
			bpf_cpumask_set_cpu(cpu, net);
			bpf_cpumask_clear_cpu(cpu, free);
			bpf_cpumask_clear_cpu(cpu, active);
			bpf_cpumask_clear_cpu(cpu, ovrflw);
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			s->nr_grows++;
		} else if (was) {
			cpuc->netstack = 0;
			bpf_cpumask_clear_cpu(cpu, net);
			if (cpuc->is_online) {
				bpf_cpumask_set_cpu(cpu, free);
				bpf_cpumask_set_cpu(cpu, active);
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			}
			s->nr_shrinks++;
		} else if (cpuc->is_online) {
			/* A CPU that came online since the last grant. */
			bpf_cpumask_set_cpu(cpu, free);
		} else {
			bpf_cpumask_clear_cpu(cpu, free);
		}
	}
	s->nr_granted = resize_nr;
	s->cap = cap;
	sys_stat.nr_netstack_cpus = resize_nr;
	bpf_rcu_read_unlock();
	return 0;
}

/*
 * The tick: answer a new request, or reconcile the grant with a CPU that
 * went offline. Runs before core compaction in update_sys_stat(), so the
 * compaction pass that follows sees the new per-CPU marks. A global
 * function, like the compaction, so that the verifier checks its loops once
 * rather than within every program that reaches update_sys_stat().
 */
__weak
int netstack_tick(void)
{
	struct netstack_shm *s;
	u64 seq;
	u32 target, flags;
	int i, words;

	if (!netstack_enabled)
		return 0;
	s = netstack_rec();
	if (!s)
		return 0;

	/* A full barrier either side of the snapshot: the record is a seqlock. */
	seq = __sync_fetch_and_add(&s->req_seq, 0);
	if (seq & 1)
		return 0;	/* a write is in progress: next tick */
	if (seq == READ_ONCE(s->applied_seq) && last_nr_cpus_onln == nr_cpus_onln)
		return 0;
	target = READ_ONCE(s->target);
	flags = READ_ONCE(s->flags);
	words = (nr_cpu_ids + 63) / 64;
	bpf_for(i, 0, words) {
		if (i >= NETSTACK_MASK_WORDS)
			break;
		req_candidates[i] = READ_ONCE(s->candidates[i]);
		req_drop[i] = READ_ONCE(s->drop[i]);
	}
	if (__sync_fetch_and_add(&s->req_seq, 0) != seq)
		return 0;	/* torn: next tick */

	if (seq != s->applied_seq)
		s->nr_requests++;
	last_nr_cpus_onln = nr_cpus_onln;
	__sync_fetch_and_add(&s->grant_seq, 1);	/* odd: the grant is being written */
	netstack_resize(s, target, flags);
	WRITE_ONCE(s->applied_seq, seq);
	__sync_fetch_and_add(&s->grant_seq, 1);	/* even: the grant is complete */
	return 0;
}

/*
 * Dispatch on a partition CPU: registered threads first, from the CPU's net
 * DSQ; then the pinned tasks that cannot run anywhere else, from the per-CPU
 * DSQ; never the shared domain queues, which would bring the application
 * back onto the CPU. A CPU freshly granted first re-enqueues what its local
 * DSQ still holds from before the grant: the kick that came with the grant
 * only preempted the running task.
 */
__hidden __attribute__ ((noinline))
void netstack_dispatch(s32 cpu, struct task_struct *prev, struct cpu_ctx *cpuc)
{
	if (cpuc->netstack & NETSTACK_CPU_FRESH) {
		cpuc->netstack &= ~NETSTACK_CPU_FRESH;
		scx_bpf_reenqueue_local_from_anywhere();
	}

	if (scx_bpf_dsq_move_to_local(cpu_to_net_dsq(cpu), 0))
		return;

	if (use_per_cpu_dsq() && scx_bpf_dsq_move_to_local(cpu_to_dsq(cpu), 0))
		return;

	consume_prev(prev, NULL, cpuc);
}

/*
 * Kick the CPU a registered thread was queued on: preempt whatever runs
 * there unless it is another registered thread, which keeps its turn.
 */
__hidden
void netstack_kick(s32 cpu, struct cpu_ctx *cpuc, bool is_idle)
{
	if (is_idle)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
	else if (!cpuc->netstack_curr)
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
}

/*
 * Create the net DSQs, one per CPU on its NUMA node, and start the free
 * mask as the online CPUs.
 */
__hidden
int netstack_init(void)
{
	struct bpf_cpumask *free;
	const struct cpumask *online;
	struct cpdom_ctx *cpdomc;
	struct cpu_ctx *cpuc;
	int cpu, err;

	if (!netstack_enabled)
		return 0;

	bpf_rcu_read_lock();
	free = netstack_free_cpumask;
	if (free) {
		online = scx_bpf_get_online_cpumask();
		bpf_cpumask_copy(free, online);
		scx_bpf_put_cpumask(online);
	}
	bpf_rcu_read_unlock();
	if (!free)
		return -ENOMEM;

	bpf_for(cpu, 0, nr_cpu_ids) {
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc) {
			scx_bpf_error("Failed to lookup cpu_ctx: %d", cpu);
			return -ESRCH;
		}
		cpdomc = MEMBER_VPTR(cpdom_ctxs, [cpuc->cpdom_id]);
		if (!cpdomc) {
			scx_bpf_error("Failed to lookup cpdom_ctx for %hhu", cpuc->cpdom_id);
			return -ESRCH;
		}
		err = scx_bpf_create_dsq(cpu_to_net_dsq(cpu), cpdomc->numa_id);
		if (err) {
			scx_bpf_error("Failed to create a net DSQ for cpu %d on NUMA node %d",
				      cpu, cpdomc->numa_id);
			return err;
		}
	}
	last_nr_cpus_onln = nr_cpus_onln;
	return 0;
}

