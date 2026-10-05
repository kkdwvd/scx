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
 * The partition is a set of pools. Pool 0 is global: its candidates are
 * every CPU. Pool 1 + d is the pool of compute domain d (an LLC, or one
 * core type of an LLC), for a stack that keeps a queue's work on the LLC
 * its interrupt lands on: its candidates are the domain's CPUs. Each pool
 * has its own request and grant, in its own entry of netstack_shm; the
 * host's cap bounds their sum, and every pool leaves at least one CPU of
 * its domain to the rest. A registered thread names its pool and runs on
 * that pool's CPUs; a thread of the global pool runs on any granted CPU.
 *
 * The stack writes a pool's request; lavd's sys_stat tick reads it and
 * answers. The tick is the only writer of the pools and of the active and
 * overflow masks, so a request cannot race the mask rebuilds of core
 * compaction, and a grant takes effect within one tick
 * (LAVD_SYS_STAT_INTERVAL_NS).
 *
 * A granted CPU is marked in its cpu_ctx (NETSTACK_CPU_GRANTED, and the
 * pool that holds it), in its pool's cpumask and in netstack_cpumask, the
 * union; netstack_free_cpumask holds the online CPUs outside the partition
 * for the paths that need the complement. Registered threads are marked in
 * their task_ctx and dispatched from a per-CPU net DSQ; foreign pinned
 * tasks keep running from the per-CPU DSQ.
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

_Static_assert(NETSTACK_MAX_POOLS == LAVD_CPDOM_MAX_NR + 1,
	       "one pool per compute domain and the global one");

/*
 * Options
 */
const volatile bool	netstack_enabled;
const volatile u32	netstack_max_cpus;	/* the host's cap on the partition, all pools */
const volatile u32	netstack_min_cpus;	/* per pool, once it has asked for any */
const volatile u64	netstack_slice_ns;	/* a registered thread's slice on a partition CPU */
/*
 * Borrowing: other tasks may run on a partition CPU's idle time, once its
 * registered threads' share has stayed below netstack_borrow_below for
 * netstack_borrow_after intervals, until it rises to netstack_borrow_above;
 * a pool that asked to be exclusive is never borrowed from.
 */
const volatile bool	netstack_borrow;
const volatile u32	netstack_borrow_below;	/* LAVD_SHIFT fixed-point */
const volatile u32	netstack_borrow_above;
const volatile u32	netstack_borrow_after;	/* intervals */

/*
 * The granted CPUs of every pool, their union, the online CPUs outside the
 * partition, and the candidates of the request being applied.
 */
private(LAVD) struct bpf_cpumask netstack_pool_cpumask[NETSTACK_MAX_POOLS];
private(LAVD) struct bpf_cpumask __kptr *netstack_cpumask;
private(LAVD) struct bpf_cpumask __kptr *netstack_free_cpumask;
private(LAVD) struct bpf_cpumask __kptr *netstack_cand_cpumask;
private(LAVD) struct bpf_cpumask __kptr *netstack_borrow_cpumask;
/*
 * Partition CPUs not running a registered thread: idle, or running a
 * borrower or a pinned task, which a registered thread placed there
 * preempts. Kept by ops.running() and ops.stopping() on partition CPUs.
 */
private(LAVD) struct bpf_cpumask __kptr *netstack_avail_cpumask;

/*
 * The shared records, one per pool. Mmapable so that a user space stack
 * can read a grant without a system call.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, NETSTACK_MAX_POOLS);
	__type(key, u32);
	__type(value, struct netstack_shm);
	__uint(map_flags, BPF_F_MMAPABLE);
} netstack_shm SEC(".maps");

/* The tick's snapshot of a request's masks, taken under the seqlock. */
static u64		req_candidates[NETSTACK_MASK_WORDS];
static u64		req_drop[NETSTACK_MASK_WORDS];
static u64		last_nr_cpus_onln;
/*
 * The grant being built, in memory rather than a register: a counter
 * carried across the loops in a register, compared against the target at
 * each step, keeps the verifier from converging the loop's states.
 */
static u32		resize_nr;

static __always_inline u32 nr_pools(void)
{
	return 1 + nr_cpdoms;
}

static __always_inline struct netstack_shm *netstack_rec(u32 pool)
{
	return bpf_map_lookup_elem(&netstack_shm, &pool);
}

static __always_inline bool mask_test(const u64 *mask, u32 cpu)
{
	if (cpu >= NETSTACK_CPU_ID_MAX)
		return false;
	return mask[cpu / 64] & (1ULL << (cpu % 64));
}

/*
 * Register or unregister @p as a network thread of @pool. Registration is
 * a field of its own in the task context rather than a flag bit: the
 * scheduler's flag updates are read-modify-writes under the task's rq
 * lock, which a writer from another context would race. The field holds
 * the pool number plus one, so that zero is unregistered.
 */
__hidden
int netstack_register_task(struct task_struct *p, u32 pool, bool on)
{
	struct netstack_shm *s;
	task_ctx *taskc;
	u32 cur;

	if (!netstack_enabled || pool >= nr_pools())
		return -ENODEV;
	taskc = find_task_ctx(p);
	if (!taskc)
		return -ESRCH;
	cur = READ_ONCE(taskc->netstack);
	if (on) {
		if (cur == pool + 1)
			return 0;
		if (cur)
			return -EEXIST;	/* of another pool: unregister first */
		s = netstack_rec(pool);
		if (!s)
			return -ENODEV;
		WRITE_ONCE(taskc->netstack, pool + 1);
		__sync_fetch_and_add(&s->nr_registered, 1);
	} else {
		if (!cur)
			return 0;
		s = netstack_rec(cur - 1);
		WRITE_ONCE(taskc->netstack, 0);
		if (s)
			__sync_fetch_and_sub(&s->nr_registered, 1);
	}
	return 0;
}

/* A registered thread exits: it leaves its pool's count. */
__hidden
void netstack_task_exit(task_ctx *taskc)
{
	struct netstack_shm *s;
	u32 cur = taskc->netstack;

	if (!cur)
		return;
	taskc->netstack = 0;
	s = netstack_rec(cur - 1);
	if (s)
		__sync_fetch_and_sub(&s->nr_registered, 1);
}


/*
 * Choose the grant of @pool for a request and apply it: keep the granted
 * candidates the stack did not drop, most preferred first in lavd's CPU
 * order; add free candidates in that order, whole cores under SMT; release
 * the rest. A CPU that joins leaves the active and overflow sets and is
 * kicked so that its running task is preempted; the first dispatch on it
 * then re-enqueues whatever its local DSQ still holds. A CPU that leaves
 * goes back to the active set; core compaction places it on its next pass.
 *
 * A global function so that the verifier checks its loops once, not within
 * every program that reaches the tick.
 */
__weak
int netstack_resize(u32 pool, u32 target, u32 flags)
{
	struct bpf_cpumask *net, *free, *cand, *active, *ovrflw, *pmask, *avail;
	const volatile u16 *cpu_order = get_cpu_order();
	const struct cpumask *online;
	struct netstack_shm *s = netstack_rec(pool);
	struct cpdom_ctx *cpdomc = NULL;
	struct bpf_cpumask *cd_cpumask = NULL;
	struct cpu_ctx *cpuc;
	u32 cap, want, cpu, others, room;
	int i, words;

	if (!s || pool >= NETSTACK_MAX_POOLS)
		return -EINVAL;
	pmask = MEMBER_VPTR(netstack_pool_cpumask, [pool]);
	if (pool) {
		cpdomc = MEMBER_VPTR(cpdom_ctxs, [pool - 1]);
		cd_cpumask = MEMBER_VPTR(cpdom_cpumask, [pool - 1]);
		if (!cpdomc || !cd_cpumask || !cpdomc->is_valid)
			return -EINVAL;
	}
	resize_nr = 0;
	bpf_rcu_read_lock();
	net = netstack_cpumask;
	free = netstack_free_cpumask;
	cand = netstack_cand_cpumask;
	active = active_cpumask;
	ovrflw = ovrflw_cpumask;
	avail = netstack_avail_cpumask;
	if (!net || !free || !cand || !active || !ovrflw || !pmask || !avail) {
		bpf_rcu_read_unlock();
		return -ENOMEM;
	}

	/*
	 * The cap: the host's over all pools less what the other pools hold,
	 * and one CPU at least left to the rest, of the pool's domain for a
	 * domain pool.
	 */
	others = bpf_cpumask_weight(cast_mask(net)) - s->nr_granted;
	cap = netstack_max_cpus > others ? netstack_max_cpus - others : 0;
	if (pool)
		room = bpf_cpumask_weight(cast_mask(cd_cpumask));
	else
		room = nr_cpus_onln;
	room = room > others + 1 ? room - others - 1 : 0;
	if (cap > room)
		cap = room;
	want = target;
	if (want && want < netstack_min_cpus)
		want = netstack_min_cpus;
	if (want > cap) {
		s->nr_denied += want - cap;
		want = cap;
	}

	/*
	 * The candidates: what the stack offered, or every CPU; online, of
	 * the pool's domain, and not held by another pool.
	 */
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
	if (pool)
		bpf_cpumask_and(cand, cast_mask(cand), cast_mask(cd_cpumask));

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
		if (cpuc->netstack_pool != pool)
			continue;	/* another pool's, or free: not this pass */
		cpuc->netstack &= ~NETSTACK_CPU_NEXT;
		if (!(cpuc->netstack & NETSTACK_CPU_GRANTED) || !cpuc->is_online)
			continue;
		if (resize_nr >= want || !bpf_cpumask_test_cpu(cpu, cast_mask(cand)) ||
		    ((flags & NETSTACK_REQ_DROP) && mask_test(req_drop, cpu)))
			continue;
		cpuc->netstack |= NETSTACK_CPU_NEXT;
		resize_nr++;
	}

	/*
	 * Pass 2: add free candidates from the least preferred end of lavd's
	 * CPU order, whole cores under SMT. The order's head is what core
	 * compaction fills first and the application's hot cores; its tail is
	 * what compaction idles first, so the partition grows into the cores
	 * the application would give up anyway and its working set moves
	 * least. The order's unfilled tail positions read as CPU 0, so a zero
	 * past the first position is skipped.
	 */
	bpf_for(i, 0, nr_cpu_ids) {
		int pos = nr_cpu_ids - 1 - i;

		if (resize_nr >= want || pos < 0 || pos >= LAVD_CPU_ID_MAX)
			break;
		cpu = cpu_order[pos];
		if (cpu >= LAVD_CPU_ID_MAX)
			break;
		if (!cpu && pos)
			continue;
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc)
			break;
		if (cpuc->netstack_pool != pool && cpuc->netstack_pool)
			continue;	/* held by another pool */
		if ((cpuc->netstack & NETSTACK_CPU_NEXT) || !cpuc->is_online ||
		    !bpf_cpumask_test_cpu(cpu, cast_mask(cand)))
			continue;
		if (is_smt_active) {
			/*
			 * Whole cores only: the per-CPU DSQ is per core, so a
			 * granted sibling would consume the other's queue. A
			 * core whose other sibling is not a free candidate, or
			 * that does not fit the target, is skipped.
			 */
			const volatile u32 *sibling = MEMBER_VPTR(cpu_sibling, [cpu]);
			struct cpu_ctx *sibc;

			if (!sibling || *sibling >= LAVD_CPU_ID_MAX)
				continue;
			if (*sibling != cpu) {
				sibc = get_cpu_ctx_id(*sibling);
				if (!sibc || resize_nr + 2 > want ||
				    !sibc->is_online ||
				    (sibc->netstack_pool && sibc->netstack_pool != pool) ||
				    !bpf_cpumask_test_cpu(*sibling, cast_mask(cand)))
					continue;
				if (!(sibc->netstack & NETSTACK_CPU_NEXT)) {
					sibc->netstack |= NETSTACK_CPU_NEXT;
					sibc->netstack_pool = pool;
					resize_nr++;
				}
			}
		}
		cpuc->netstack |= NETSTACK_CPU_NEXT;
		cpuc->netstack_pool = pool;
		resize_nr++;
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
		if (cpuc->netstack_pool != pool) {
			/* Another pool's or free: keep the free mask current. */
			if (!cpuc->netstack_pool) {
				if (cpuc->is_online)
					bpf_cpumask_set_cpu(cpu, free);
				else
					bpf_cpumask_clear_cpu(cpu, free);
			}
			continue;
		}
		was = cpuc->netstack & NETSTACK_CPU_GRANTED;
		now = cpuc->netstack & NETSTACK_CPU_NEXT;
		if (now) {
			s->granted[cpu / 64] |= 1ULL << (cpu % 64);
			if (was) {
				cpuc->netstack &= ~NETSTACK_CPU_NEXT;
				continue;
			}
			cpuc->netstack = NETSTACK_CPU_GRANTED | NETSTACK_CPU_FRESH;
			bpf_cpumask_set_cpu(cpu, pmask);
			bpf_cpumask_set_cpu(cpu, net);
			bpf_cpumask_set_cpu(cpu, avail);
			bpf_cpumask_clear_cpu(cpu, free);
			bpf_cpumask_clear_cpu(cpu, active);
			bpf_cpumask_clear_cpu(cpu, ovrflw);
			scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
			s->nr_grows++;
		} else {
			cpuc->netstack_pool = 0;
			if (!was)
				continue;
			cpuc->netstack = 0;
			cpuc->netstack_idle_ticks = 0;
			bpf_cpumask_clear_cpu(cpu, pmask);
			bpf_cpumask_clear_cpu(cpu, net);
			bpf_cpumask_clear_cpu(cpu, avail);
			if (cpuc->is_online) {
				bpf_cpumask_set_cpu(cpu, free);
				bpf_cpumask_set_cpu(cpu, active);
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
			}
			s->nr_shrinks++;
		}
	}
	s->nr_granted = resize_nr;
	s->cap = cap;
	sys_stat.nr_netstack_cpus = bpf_cpumask_weight(cast_mask(net));
	bpf_rcu_read_unlock();
	return 0;
}

/*
 * Answer @pool's request when it has a new one, or when a CPU went offline
 * since the last grant.
 */
static __always_inline void netstack_apply(u32 pool, bool hotplug)
{
	struct netstack_shm *s = netstack_rec(pool);
	u64 seq;
	u32 target, flags;
	int i, words;

	if (!s)
		return;
	/* A full barrier either side of the snapshot: the record is a seqlock. */
	seq = __sync_fetch_and_add(&s->req_seq, 0);
	if (seq & 1)
		return;		/* a write is in progress: next tick */
	if (seq == READ_ONCE(s->applied_seq) && !(hotplug && s->nr_granted))
		return;
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
		return;		/* torn: next tick */

	if (seq != s->applied_seq)
		s->nr_requests++;
	__sync_fetch_and_add(&s->grant_seq, 1);	/* odd: the grant is being written */
	netstack_resize(pool, target, flags);
	WRITE_ONCE(s->applied_seq, seq);
	__sync_fetch_and_add(&s->grant_seq, 1);	/* even: the grant is complete */
}

/*
 * The borrowing gate, per partition CPU and interval. Other tasks may use
 * a partition CPU only once its registered threads have left most of it
 * idle for a while: a sustained shortfall of use, not a momentary gap, and
 * never on a pool that asked to be exclusive. The gate shuts as soon as the
 * registered share rises again; the kick that queues a registered thread
 * preempts a borrower at once in any case, and a borrower whose CPU shut
 * the gate is evicted at its next dispatch. A CPU with the gate open and
 * nothing of its own to run is woken when its domain queue has work.
 */
static __always_inline void netstack_borrow_gate(void)
{
	struct bpf_cpumask *borrow = netstack_borrow_cpumask;
	struct netstack_shm *s;
	struct cpu_ctx *cpuc;
	u32 cpu, nr = 0;
	bool open, exclusive;

	if (!borrow)
		return;
	bpf_for(cpu, 0, nr_cpu_ids) {
		if (cpu >= LAVD_CPU_ID_MAX)
			break;
		cpuc = get_cpu_ctx_id(cpu);
		if (!cpuc)
			break;
		if (!(cpuc->netstack & NETSTACK_CPU_GRANTED)) {
			if (cpuc->netstack & NETSTACK_CPU_BORROW) {
				cpuc->netstack &= ~NETSTACK_CPU_BORROW;
				bpf_cpumask_clear_cpu(cpu, borrow);
			}
			continue;
		}
		s = netstack_rec(cpuc->netstack_pool);
		exclusive = !s || (READ_ONCE(s->flags) & NETSTACK_REQ_EXCLUSIVE);
		open = cpuc->netstack & NETSTACK_CPU_BORROW;
		if (!netstack_borrow || exclusive || !use_cpdom_dsq()) {
			open = false;
			cpuc->netstack_idle_ticks = 0;
		} else if (open) {
			if (cpuc->cur_netstack_util_wall >= netstack_borrow_above) {
				open = false;
				cpuc->netstack_idle_ticks = 0;
			}
		} else if (cpuc->cur_netstack_util_wall <= netstack_borrow_below) {
			if (cpuc->netstack_idle_ticks < 255)
				cpuc->netstack_idle_ticks++;
			open = cpuc->netstack_idle_ticks >= netstack_borrow_after;
		} else {
			cpuc->netstack_idle_ticks = 0;
		}
		if (open) {
			cpuc->netstack |= NETSTACK_CPU_BORROW;
			bpf_cpumask_set_cpu(cpu, borrow);
			nr++;
			/* Idle with work waiting in its domain: wake it to borrow. */
			if ((scx_bpf_dsq_nr_queued(cpdom_to_dsq(cpuc->cpdom_id)) ||
			     scx_bpf_dsq_nr_queued(cpdom_to_turb_dsq(cpuc->cpdom_id))) &&
			    scx_bpf_test_and_clear_cpu_idle(cpu))
				scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		} else {
			cpuc->netstack &= ~NETSTACK_CPU_BORROW;
			bpf_cpumask_clear_cpu(cpu, borrow);
		}
	}
	sys_stat.nr_netstack_borrow = nr;
}

/*
 * The tick: answer the pools' new requests, reconcile every grant with a
 * CPU that went offline, and run the borrowing gate. Runs before core
 * compaction in update_sys_stat(), so the compaction pass that follows
 * sees the new per-CPU marks.
 */
__weak
int netstack_tick(void)
{
	bool hotplug;
	u32 pool;

	if (!netstack_enabled)
		return 0;
	hotplug = last_nr_cpus_onln != nr_cpus_onln;
	last_nr_cpus_onln = nr_cpus_onln;
	bpf_for(pool, 0, nr_pools()) {
		if (pool >= NETSTACK_MAX_POOLS)
			break;
		netstack_apply(pool, hotplug);
	}
	bpf_rcu_read_lock();
	netstack_borrow_gate();
	bpf_rcu_read_unlock();
	return 0;
}

/*
 * A task found no idle CPU of its own: wake an idle partition CPU of its
 * domain that is open to borrowing, if there is one, so that it pulls the
 * task from the domain queue.
 */
__hidden
void netstack_borrow_kick(struct task_struct *p, struct cpu_ctx *cpuc_cur)
{
	struct bpf_cpumask *borrow = netstack_borrow_cpumask;
	struct bpf_cpumask *tmp = cpuc_cur->temp_mask;
	s32 cpu;

	if (!borrow || !tmp || bpf_cpumask_empty(cast_mask(borrow)))
		return;
	bpf_cpumask_and(tmp, cast_mask(borrow), p->cpus_ptr);
	cpu = scx_bpf_pick_idle_cpu(cast_mask(tmp), 0);
	if (cpu >= 0)
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
}

/*
 * A CPU freshly granted may hold, in its per-CPU DSQ, tasks queued there
 * before the grant that could run elsewhere: under --per-cpu-dsq every
 * task of the CPU, under --warm-cpu-us those waiting for it to warm up.
 * Move them to active CPUs, each to the queue that CPU consumes; the
 * pinned and migration-disabled tasks stay, they can run nowhere else.
 */
static __always_inline void netstack_drain(s32 cpu)
{
	struct bpf_cpumask *active = active_cpumask;
	struct task_struct *p;
	struct cpu_ctx *tcpuc;
	s32 target;

	if (!active)
		return;
	bpf_for_each(scx_dsq, p, cpu_to_dsq(cpu), 0) {
		if (p->nr_cpus_allowed == 1 || is_migration_disabled(p))
			continue;
		target = bpf_cpumask_any_and_distribute(cast_mask(active), p->cpus_ptr);
		if (target >= nr_cpu_ids)
			continue;
		tcpuc = get_cpu_ctx_id(target);
		if (!tcpuc)
			continue;
		/*
		 * By vtime: lavd's queues are priority queues, and a DSQ
		 * takes either kind of insert but not both.
		 */
		if (scx_bpf_dsq_move_vtime(BPF_FOR_EACH_ITER, p,
					   use_cpdom_dsq() ? cpdom_to_dsq(tcpuc->cpdom_id) :
							     cpu_to_dsq(target), 0))
			scx_bpf_kick_cpu(target, SCX_KICK_IDLE);
	}
}

/*
 * Dispatch on a partition CPU: registered threads first, from the CPU's net
 * DSQ; then the pinned tasks that cannot run anywhere else, from the per-CPU
 * DSQ; never the shared domain queues, which would bring the application
 * back onto the CPU. A CPU freshly granted first re-enqueues what its local
 * DSQ still holds from before the grant, since the kick that came with the
 * grant only preempted the running task, and drains its per-CPU DSQ of the
 * tasks that could run elsewhere.
 */
__hidden __attribute__ ((noinline))
void netstack_dispatch(s32 cpu, struct task_struct *prev, struct cpu_ctx *cpuc)
{
	if (cpuc->netstack & NETSTACK_CPU_FRESH) {
		cpuc->netstack &= ~NETSTACK_CPU_FRESH;
		scx_bpf_reenqueue_local_from_anywhere();
		netstack_drain(cpu);
	}

	if (scx_bpf_dsq_move_to_local(cpu_to_net_dsq(cpu), 0))
		return;

	if (scx_bpf_dsq_move_to_local(cpu_to_dsq(cpu), 0))
		return;

	/*
	 * Nothing of the partition's: with the borrowing gate open, take a
	 * task from the domain's queues; the kick that queues a registered
	 * thread preempts it again.
	 */
	if (cpuc->netstack & NETSTACK_CPU_BORROW) {
		if (scx_bpf_dsq_move_to_local(cpdom_to_dsq(cpuc->cpdom_id), 0))
			return;
		if (scx_bpf_dsq_move_to_local(cpdom_to_turb_dsq(cpuc->cpdom_id), 0))
			return;
	}

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
 * Create the net DSQs, one per CPU on its NUMA node, start the free mask
 * as the online CPUs, and label the pool records.
 */
__hidden
int netstack_init(void)
{
	struct bpf_cpumask *free;
	const struct cpumask *online;
	struct netstack_shm *s;
	struct cpdom_ctx *cpdomc;
	struct cpu_ctx *cpuc;
	u32 pool;
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

	bpf_for(pool, 0, nr_pools()) {
		if (pool >= NETSTACK_MAX_POOLS)
			break;
		s = netstack_rec(pool);
		if (!s)
			return -ENOENT;
		s->pool = pool;
		s->cpdom = pool ? pool - 1 : NETSTACK_POOL_GLOBAL_CPDOM;
	}

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

/*
 * The syscall programs: the stack's side of the records, run with
 * BPF_PROG_TEST_RUN on the programs pinned under lavd's netstack directory.
 * They are sleepable and run in the caller's context, so every use of a
 * task context is inside an RCU read-side section.
 */

/* Copy the grant in force into @nr, @seq, @req and @mask, under its seqlock. */
static __always_inline int netstack_read_grant(struct netstack_shm *s, u32 *nr,
					       u32 *target, u32 *cap, u64 *seq,
					       u64 *applied, u64 *mask)
{
	u64 s1, s2;
	int i, words = (nr_cpu_ids + 63) / 64, tries = 0;

	do {
		s1 = __sync_fetch_and_add(&s->grant_seq, 0);
		if (s1 & 1)
			continue;
		*nr = READ_ONCE(s->nr_granted);
		*target = READ_ONCE(s->target);
		*cap = READ_ONCE(s->cap);
		*applied = READ_ONCE(s->applied_seq);
		bpf_for(i, 0, words) {
			if (i >= NETSTACK_MASK_WORDS)
				break;
			mask[i] = READ_ONCE(s->granted[i]);
		}
		s2 = __sync_fetch_and_add(&s->grant_seq, 0);
		if (s1 == s2) {
			*seq = s1;
			return 0;
		}
	} while (++tries < 64 && can_loop);
	return -EAGAIN;
}

static __always_inline struct task_struct *netstack_arg_task(s32 tid)
{
	if (tid)
		return bpf_task_from_pid(tid);
	return bpf_task_acquire(bpf_get_current_task_btf());
}

static int netstack_set_thread(struct netstack_thread_arg *arg, bool on)
{
	struct task_struct *p;
	int err;

	if (!netstack_enabled)
		return -ENODEV;
	if (arg->flags || arg->pool >= nr_pools())
		return -EINVAL;
	p = netstack_arg_task(arg->tid);
	if (!p)
		return -ESRCH;
	bpf_rcu_read_lock();
	err = netstack_register_task(p, arg->pool, on);
	bpf_rcu_read_unlock();
	bpf_task_release(p);
	return err;
}

SEC("syscall")
int lavd_netstack_register_thread(struct netstack_thread_arg *arg)
{
	return netstack_set_thread(arg, true);
}

SEC("syscall")
int lavd_netstack_unregister_thread(struct netstack_thread_arg *arg)
{
	return netstack_set_thread(arg, false);
}

SEC("syscall")
int lavd_netstack_get_capacity(struct netstack_cap_arg *arg)
{
	struct netstack_shm *s;
	int err;

	if (!netstack_enabled)
		return -ENODEV;
	if (arg->pool >= nr_pools() || !(s = netstack_rec(arg->pool)))
		return -EINVAL;
	err = netstack_read_grant(s, &arg->nr_granted, &arg->target, &arg->cap,
				  &arg->grant_seq, &arg->req_seq, arg->granted);
	if (err)
		return err;
	return arg->nr_granted;
}

SEC("syscall")
int lavd_netstack_request_capacity(struct netstack_req_arg *arg)
{
	struct netstack_shm *s;
	u64 seq;
	u32 cap, target;
	int i, err, words = (nr_cpu_ids + 63) / 64;

	if (!netstack_enabled)
		return -ENODEV;
	if (arg->pool >= nr_pools() || !(s = netstack_rec(arg->pool)) ||
	    (arg->flags & ~(NETSTACK_REQ_CANDIDATES | NETSTACK_REQ_DROP |
			    NETSTACK_REQ_EXCLUSIVE)))
		return -EINVAL;	/* the other flags are reserved */
	if (arg->target_cpus < -1)
		return -EINVAL;	/* a target beyond the cap is granted the cap */

	/*
	 * Take the record's seqlock: even to odd, and only from the value
	 * read, so that a second requester fails instead of tearing the
	 * first's write.
	 */
	seq = __sync_fetch_and_add(&s->req_seq, 0);
	if ((seq & 1) || __sync_val_compare_and_swap(&s->req_seq, seq, seq + 1) != seq)
		return -EBUSY;
	if (arg->target_cpus >= 0)
		WRITE_ONCE(s->target, arg->target_cpus);
	WRITE_ONCE(s->flags, arg->flags);
	bpf_for(i, 0, words) {
		if (i >= NETSTACK_MASK_WORDS)
			break;
		if (arg->flags & NETSTACK_REQ_CANDIDATES)
			WRITE_ONCE(s->candidates[i], arg->candidates[i]);
		if (arg->flags & NETSTACK_REQ_DROP)
			WRITE_ONCE(s->drop[i], arg->drop[i]);
	}
	__sync_fetch_and_add(&s->req_seq, 1);
	arg->req_seq = seq + 2;

	/* The grant in force now: the one the next tick replaces. */
	err = netstack_read_grant(s, &arg->nr_granted, &target, &cap, &seq, &seq,
				  arg->granted);
	if (err)
		return err;
	return arg->nr_granted;
}
