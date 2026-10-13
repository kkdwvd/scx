/* SPDX-License-Identifier: GPL-2.0-only */
/* Extracted callback bodies: Copyright (c) Meta Platforms, Inc. and affiliates. */
/* Source SHA-256: 882f0c50fcdd5f2d15dbecb25bb6e4d0deba15ea867da3df84d91cad1de77b20 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
typedef uint64_t u64; typedef uint32_t u32; typedef int32_t s32;
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x,v) ((x)=(v))
#define unlikely(x) (x)
#define MEMBER_VPTR(base,member) (tctx->cell < 2 ? &(base member) : NULL)
#define scx_bpf_error(...) (++errors)
#define cstat_inc(...) ((void)0)
#define SCX_TASK_QUEUED 1
#define MAX_LLCS 2
#define FAKE_FLAT_SUBCELL_LLC 0
#define PINNED_MAX_WAIT_SLICES 8
#define DEMAND_SHIFT 10
#define DEMAND_TAU_NS (100ULL*1000*1000)
#define DEMAND_MAX_WINDOW_NS (1ULL<<40)
typedef struct { u64 raw; } dsq_id_t;
#define DSQ_INVALID ((dsq_id_t){0})
struct task_struct { int pid, cpu; struct { u64 flags,slice,dsq_vtime; u32 weight; } scx; } task;
struct task_ctx {
 u32 cell,subcell,llc,vtime_charge_subcell,demand;
 bool all_cell_cpus_allowed,borrowed;
 dsq_id_t dsq;
 u64 avg_runtime_ns,started_running_at,running_accounted_at,runnable_at,quiescent_at;
 u64 demand_window_at,window_run_ns,window_sleep_ns;
} taskctx;
struct cpu_ctx { u32 cell,subcell,llc; u64 vtime_now,running_ns[2],pinned_waiting_since; } cpus[2];
struct subcell { u64 llcs_to_drain; } sub;
struct subcell_account { u64 running_ns,queued_ns,demand_sum; } accounts[2][4];
int subcell_accounts,executing,errors,refills; bool map_fail;
u64 local_time[2],task_time[2],global_time,slice_ns=20000000;
bool enable_llc_awareness,enable_slice_shrinking; u32 nr_llc=1;
static inline u64 time_delta(u64 after,u64 before) { return (int64_t)(after-before)>0 ? after-before : 0; }
static inline bool time_before(u64 a,u64 b) { return (int64_t)(a-b)<0; }
static u64 scx_bpf_now(void) { return local_time[executing]; }
static u64 bpf_ktime_get_ns(void) { return global_time; }
static u64 scx_clock_task(u32 cpu) { return task_time[cpu]; }
static int scx_bpf_task_cpu(struct task_struct *p) { return p->cpu; }
static struct cpu_ctx *lookup_cpu_ctx(int cpu) { return &cpus[cpu<0 ? executing : cpu]; }
static struct task_ctx *lookup_task_ctx(struct task_struct *p) { return &taskctx; }
static s32 pack_subcell_id(u32 cell,u32 subcell) {
 if(cell>=2 || subcell>=2) { ++errors; return -EINVAL; } return cell*2+subcell;
}
static void *bpf_map_lookup_elem(void *map,u32 *key) { return map_fail ? NULL : &accounts[executing][*key]; }
static void *bpf_map_lookup_percpu_elem(void *map,u32 *key,u32 cpu) { return map_fail ? NULL : &accounts[cpu][*key]; }
static dsq_id_t get_cpu_dsq_id(int cpu) { return (dsq_id_t){100+cpu}; }
static dsq_id_t get_subcell_llc_dsq_id(u32 c,u32 s,u32 l) { return (dsq_id_t){200+c*2+s}; }
static bool dsq_is_invalid(dsq_id_t dsq) { return !dsq.raw; }
static struct task_struct *dsq_peek(u64 id) { return NULL; }
static struct subcell *lookup_subcell(u32 c,u32 s) { return &sub; }
static int try_draining_work(u32 c,u32 s,u32 l,struct cpu_ctx *ctx) { return 1; }
static int try_stealing_work(u32 c,u32 s,u32 l) { return 1; }
static bool task_needs_refresh(struct task_struct *p,struct task_ctx *ctx) { return false; }
static void scx_bpf_task_set_slice(struct task_struct *p,u64 slice) { ++refills; p->scx.slice=slice; }
static bool scx_bpf_dsq_move_to_local(u64 id,u64 flags) { return false; }
static void subcell_llc_nr_queued_dec(struct subcell *s,u32 l) { }
static int maybe_update_task_llc(struct task_struct *p,struct task_ctx *t,int cpu) { return 0; }
static void advance_subcell_llc_vtime(struct subcell *s,u32 llc,u64 vtime) { }
static int slice_shrink_on_running(struct task_struct *p,u32 cell,struct cpu_ctx *c) { return 0; }
static bool llc_is_valid(u32 llc) { return llc<2; }
static void scx_bpf_task_set_dsq_vtime(struct task_struct *p,u64 vtime) { p->scx.dsq_vtime=vtime; }
static __always_inline bool pinned_dsq_overdue(struct cpu_ctx *cctx)
{
	u64 since = READ_ONCE(cctx->pinned_waiting_since);

	return since && time_delta(scx_bpf_now(), since) > PINNED_MAX_WAIT_SLICES * slice_ns;
}
static __always_inline void update_task_demand(struct task_ctx *tctx, struct subcell_account *account, u64 now,
					       bool stopping)
{
	u64 window, active;

	if (!tctx->demand_window_at) {
		tctx->demand_window_at = now;
		tctx->window_run_ns = 0;
		tctx->window_sleep_ns = 0;
		return;
	}

	window = time_delta(now, tctx->demand_window_at);
	if (!window || (!stopping && window < DEMAND_TAU_NS))
		return;
	if (window > DEMAND_MAX_WINDOW_NS)
		window = DEMAND_MAX_WINDOW_NS;

	active = tctx->window_run_ns + tctx->window_sleep_ns;
	if (active) {
		u64 sample = (tctx->window_run_ns << DEMAND_SHIFT) / active;
		u64 demand = tctx->demand;

		/* BPF has no signed division; move toward the sample by hand. */
		if (sample >= demand)
			demand += (sample - demand) * window / (window + DEMAND_TAU_NS);
		else
			demand -= (demand - sample) * window / (window + DEMAND_TAU_NS);
		tctx->demand = demand;
	}

	account->demand_sum += (u64)tctx->demand * window;
	tctx->demand_window_at = now;
	tctx->window_run_ns = 0;
	tctx->window_sleep_ns = 0;
}
static __always_inline int account_task_running(s32 cpu, struct cpu_ctx *cctx, struct task_ctx *tctx, u64 now,
						bool stopping)
{
	u64 *running = MEMBER_VPTR(cctx->running_ns, [tctx->cell]);
	struct subcell_account *account;
	s32 packed;
	u32 key;
	u64 used;

	if (!running) {
		scx_bpf_error("Task cell index too large: %d", tctx->cell);
		return -EINVAL;
	}
	packed = pack_subcell_id(tctx->cell, tctx->subcell);
	if (packed < 0)
		return packed;
	key = packed;
	account = bpf_map_lookup_percpu_elem(&subcell_accounts, &key, cpu);
	if (!account) {
		scx_bpf_error("Task cell or subcell index too large: %d, %d", tctx->cell, tctx->subcell);
		return -ENOENT;
	}
	used = time_delta(now, tctx->running_accounted_at);
	tctx->running_accounted_at = now;
	*running += used;
	account->running_ns += used;
	tctx->window_run_ns += used;
	/* Demand windows span sleeps and migrations, so use elapsed wall time. */
	update_task_demand(tctx, account, bpf_ktime_get_ns(), stopping);
	return 0;
}
void BPF_STRUCT_OPS(mitosis_dispatch, s32 cpu, struct task_struct *prev)
{
	struct cpu_ctx *cctx;
	u32 cell;
	u32 subcell_id;

	if (!(cctx = lookup_cpu_ctx(cpu)))
		return;

	cell = READ_ONCE(cctx->cell);
	subcell_id = READ_ONCE(cctx->subcell);

	bool found = false;
	dsq_id_t min_vtime_dsq = DSQ_INVALID;
	u64 min_vtime = 0;

	struct task_struct *p;

	/* Check the CPU's subcell-LLC DSQ. */
	u32 llc = enable_llc_awareness ? cctx->llc : FAKE_FLAT_SUBCELL_LLC;
	dsq_id_t subcell_dsq = get_subcell_llc_dsq_id(cell, subcell_id, llc);
	dsq_id_t cpu_dsq = get_cpu_dsq_id(cpu);

	if (dsq_is_invalid(subcell_dsq) || dsq_is_invalid(cpu_dsq))
		return;

	if (enable_llc_awareness) {
		struct subcell *subcell = lookup_subcell(cell, subcell_id);

		if (!subcell)
			return;

		if (READ_ONCE(subcell->llcs_to_drain)) {
			s32 ret = try_draining_work(cell, subcell_id, llc, cctx);

			if (!ret) {
				cstat_inc(CSTAT_DRAIN_CNT, cell, cctx);
				return;
			}
		}
	}

	/* Peek at the subcell-LLC DSQ head. */
	p = dsq_peek(subcell_dsq.raw);
	if (p) {
		min_vtime = p->scx.dsq_vtime;
		min_vtime_dsq = subcell_dsq;
		found = true;
	}

	/*
	 * Peek at CPU DSQ head, prefer if lower vtime. Under a deep subcell
	 * backlog the pinned head can lose every comparison for a full round
	 * of the queue, so also bound how long the per-CPU DSQ goes unserved.
	 */
	p = dsq_peek(cpu_dsq.raw);
	if (p) {
		bool overdue = pinned_dsq_overdue(cctx);

		if (!found || overdue || time_before(p->scx.dsq_vtime, min_vtime)) {
			min_vtime = p->scx.dsq_vtime;
			min_vtime_dsq = cpu_dsq;
			found = true;
		}
	} else {
		WRITE_ONCE(cctx->pinned_waiting_since, 0);
	}

	/* If we failed to find an eligible task, try the sibling LLC DSQs. */
	if (!found) {
		if (enable_llc_awareness && !try_stealing_work(cell, subcell_id, llc)) {
			cstat_inc(CSTAT_STEAL, cell, cctx);
			return;
		}

		/*
		 * Nothing to run. Extend the slice of a still-runnable prev
		 * whose placement is current and still names this cpu.
		 * Otherwise let the SCX_ENQ_LAST enqueue re-place the task, its
		 * kicks provide the follow-up scheduling event while this cpu
		 * goes idle.
		 */
		if (prev && (prev->scx.flags & SCX_TASK_QUEUED)) {
			struct task_ctx *tctx;
			bool stay = false;

			if (!(tctx = lookup_task_ctx(prev)))
				return;

			if (!task_needs_refresh(prev, tctx)) {
				if (tctx->all_cell_cpus_allowed)
					stay = tctx->cell == cell && tctx->subcell == subcell_id;
				else
					stay = tctx->dsq.raw == cpu_dsq.raw;
			}

			if (stay) {
				/*
				 * This is an accounting hook as well as a refill.
				 * Once prev's slice is extended the core picks it
				 * again, and put_prev_set_next_task() returns early
				 * for next == prev, so neither stopping() nor
				 * running() fires for as long as prev stays alone on
				 * this cpu. Charge any runtime accumulated since the
				 * last tick or slice extension, and let stopping()
				 * charge the remainder.
				 */
				if (account_task_running(cpu, cctx, tctx, scx_clock_task(cpu), false) < 0)
					return;
				scx_bpf_task_set_slice(prev, slice_ns);
			}
		}
		return;
	}

	/*
	 * A head can leave between the peek and the move, consumed by another
	 * CPU in the subcell or dequeued. Fall back to the other DSQ instead of
	 * idling with its head queued.
	 */
	if (!scx_bpf_dsq_move_to_local(min_vtime_dsq.raw, 0)) {
		min_vtime_dsq = min_vtime_dsq.raw == subcell_dsq.raw ? cpu_dsq : subcell_dsq;
		if (!scx_bpf_dsq_move_to_local(min_vtime_dsq.raw, 0))
			return;
	}

	/*
	 * Served the per-CPU DSQ: restart its wait clock. If it is now empty
	 * the next dispatch's peek clears it.
	 */
	if (min_vtime_dsq.raw == cpu_dsq.raw) {
		WRITE_ONCE(cctx->pinned_waiting_since, scx_bpf_now());
	} else if (enable_llc_awareness) {
		struct subcell *subcell = lookup_subcell(cell, subcell_id);

		if (subcell)
			subcell_llc_nr_queued_dec(subcell, llc);
	}
}
static __always_inline int account_task_queued(struct task_ctx *tctx, u64 now)
{
	struct subcell_account *account;
	s32 packed;
	u32 key;

	if (!tctx->runnable_at)
		return 0;

	packed = pack_subcell_id(tctx->cell, tctx->subcell);
	if (packed < 0)
		return packed;
	key = packed;
	account = bpf_map_lookup_elem(&subcell_accounts, &key);
	if (!account) {
		scx_bpf_error("Task cell or subcell index too large: %d, %d", tctx->cell, tctx->subcell);
		return -ENOENT;
	}
	account->queued_ns += time_delta(now, tctx->runnable_at);
	tctx->runnable_at = 0;
	return 0;
}
void BPF_STRUCT_OPS(mitosis_runnable, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	u64 now;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	now = bpf_ktime_get_ns();
	if (tctx->quiescent_at) {
		tctx->window_sleep_ns += time_delta(now, tctx->quiescent_at);
		tctx->quiescent_at = 0;
	}
	tctx->runnable_at = now;
}
void BPF_STRUCT_OPS(mitosis_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	if (!(tctx = lookup_task_ctx(p)))
		return;

	u64 now = bpf_ktime_get_ns();

	/* Dequeued without running again: close the wait it was in, if any. */
	if (account_task_queued(tctx, now) < 0)
		return;
	tctx->quiescent_at = now;
}
void BPF_STRUCT_OPS(mitosis_running, struct task_struct *p)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct subcell *subcell;
	u64 now;

	if (!(cctx = lookup_cpu_ctx(scx_bpf_task_cpu(p))) || !(tctx = lookup_task_ctx(p)))
		return;

	if (enable_llc_awareness && tctx->all_cell_cpus_allowed) {
		/*
		 * The actual running CPU is known once the task starts running
		 * after dispatch or sibling LLC stealing. Refresh the task's LLC
		 * here so its assignment and vtime domain follow where it really
		 * ran.
		 */
		if (maybe_update_task_llc(p, tctx, scx_bpf_task_cpu(p)) < 0)
			return;

		s32 llc = tctx->llc;
		if (llc >= 0 && llc < MAX_LLCS && (subcell = lookup_subcell(tctx->cell, tctx->subcell)))
			advance_subcell_llc_vtime(subcell, (u32)llc, p->scx.dsq_vtime);
	}

	now = bpf_ktime_get_ns();
	/* The task waited from its last runnable mark until now. */
	if (account_task_queued(tctx, now) < 0)
		return;
	/* Record the running slice start time. */
	tctx->started_running_at = scx_bpf_now();
	tctx->running_accounted_at = scx_clock_task(scx_bpf_task_cpu(p));

	/* Shrink our slice if a pinned task is queued on this CPU's DSQ. */
	if (enable_slice_shrinking) {
		int ret = slice_shrink_on_running(p, tctx->cell, cctx);
		if (ret < 0)
			return;
	}
}
static inline void update_task_runtime_ewma(struct task_ctx *tctx, u64 used)
{
	if (unlikely(!tctx->avg_runtime_ns))
		/* Init */
		tctx->avg_runtime_ns = used;
	else
		tctx->avg_runtime_ns = (tctx->avg_runtime_ns * 7 + used) / 8;
}
void BPF_STRUCT_OPS(mitosis_tick, struct task_struct *p)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;

	if (!(cctx = lookup_cpu_ctx(scx_bpf_task_cpu(p))) || !(tctx = lookup_task_ctx(p)))
		return;
	if (account_task_running(scx_bpf_task_cpu(p), cctx, tctx, scx_clock_task(scx_bpf_task_cpu(p)), false) < 0)
		return;
}
void BPF_STRUCT_OPS(mitosis_stopping, struct task_struct *p, bool runnable)
{
	struct cpu_ctx *cctx;
	struct task_ctx *tctx;
	struct subcell *subcell;
	u64 now, used;
	u32 cidx;
	u32 subcell_idx;
	s32 packed_subcell;

	if (!(cctx = lookup_cpu_ctx(scx_bpf_task_cpu(p))) || !(tctx = lookup_task_ctx(p)))
		return;

	/*
	 * Use CPU's cell (not task's cell) to match dispatch() logic.
	 * Prevents starvation when a task is pinned outside its cell.
	 * E.g. a cell 0 kworker pinned to a cell 1 CPU.
	 */
	cidx = cctx->cell;
	subcell_idx = cctx->subcell;
	if (!(subcell = lookup_subcell(cidx, subcell_idx)))
		return;
	packed_subcell = pack_subcell_id(cidx, subcell_idx);
	if (packed_subcell < 0)
		return;

	now = scx_bpf_now();
	/*
	 * scx_bpf_now() is per-CPU (uses this_rq()) and not monotonic
	 * across CPUs. Clamp negative deltas to zero to prevent
	 * unsigned underflow from corrupting vtime.
	 */
	if (now < tctx->started_running_at)
		cstat_inc(CSTAT_CLAMP_USED, cidx, cctx);
	used = time_delta(now, tctx->started_running_at);
	tctx->started_running_at = now;

	update_task_runtime_ewma(tctx, used);

	/* scale the execution time by the inverse of the weight and charge */
	if (p->scx.weight == 0) {
		scx_bpf_error("Task %d has zero weight", p->pid);
		return;
	}
	scx_bpf_task_set_dsq_vtime(p, p->scx.dsq_vtime + (used * 100 / p->scx.weight));

	/*
	 * Only advance this CPU's local vtime when the slice ends on a CPU
	 * whose subcell matches this task's vtime charge subcell and the task
	 * was not borrowed. If execution ends in some other subcell, drop the
	 * local charge rather than risk charging an unexpected subcell.
	 */
	if (!tctx->borrowed && tctx->vtime_charge_subcell == packed_subcell) {
		if (time_before(READ_ONCE(cctx->vtime_now), p->scx.dsq_vtime))
			WRITE_ONCE(cctx->vtime_now, p->scx.dsq_vtime);
	}

	/*
	 * Only advance subcell vtime when the task stops on a CPU whose subcell
	 * still matches this task's vtime charge subcell and the task was not
	 * borrowed. If the CPU was retagged into a different subcell after the
	 * task was placed, drop the charge rather than advance the wrong domain.
	 */
	if (!tctx->borrowed && tctx->vtime_charge_subcell == packed_subcell) {
		u32 llc_idx = FAKE_FLAT_SUBCELL_LLC;

		if (enable_llc_awareness) {
			if (!llc_is_valid(cctx->llc) || cctx->llc >= nr_llc) {
				scx_bpf_error("invalid CPU LLC in stopping: %u", cctx->llc);
				return;
			}
			llc_idx = cctx->llc;
		}
		advance_subcell_llc_vtime(subcell, llc_idx, p->scx.dsq_vtime);
	}

	/* Clear the borrowed flag — it is one-shot, consumed above */
	tctx->borrowed = false;

	/* Charge whatever the slice extensions since the last flush left over. */
	now = bpf_ktime_get_ns();
	if (account_task_running(scx_bpf_task_cpu(p), cctx, tctx, scx_clock_task(scx_bpf_task_cpu(p)), true) < 0)
		return;

	/* A preempted task is still runnable; its next wait starts now. */
	tctx->runnable_at = runnable ? now : 0;
}
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"%s:%d: %s\n",name,__LINE__,#c); return 1; } } while(0)
static void clock_at(u64 now) { global_time=now; local_time[0]=local_time[1]=now; task_time[0]=task_time[1]=now; }
int main(int argc,char **argv) {
 const char *name=argv[1];
 task.cpu=1; task.pid=42; task.scx.flags=SCX_TASK_QUEUED; task.scx.weight=100;
 taskctx.dsq=get_cpu_dsq_id(1); taskctx.running_accounted_at=1000; taskctx.started_running_at=1000;
 clock_at(1500);
 if(!strcmp(name,"remote-context")) {
  cpus[0].cell=1; mitosis_dispatch(1,&task);
  CHECK(cpus[1].running_ns[0]==500); CHECK(cpus[0].running_ns[0]==0);
 } else if(!strcmp(name,"remote-clock")) {
  executing=1; clock_at(1000); mitosis_running(&task);
  executing=0; clock_at(1500); local_time[0]=500; task_time[0]=500;
  mitosis_dispatch(1,&task);
  CHECK(cpus[0].running_ns[0]+cpus[1].running_ns[0]==500);
  CHECK(cpus[1].running_ns[0]==500);
  CHECK(taskctx.running_accounted_at==1500);
 } else if(!strcmp(name,"remote-subcell")) {
  mitosis_dispatch(1,&task); CHECK(accounts[1][0].running_ns==500); CHECK(accounts[0][0].running_ns==0);
 } else if(!strcmp(name,"queued-clock")) {
  global_time=5000; local_time[0]=1000; mitosis_runnable(&task,0);
  executing=1; global_time=5100; local_time[1]=200; mitosis_running(&task);
  CHECK(accounts[1][0].queued_ns==100); CHECK(taskctx.runnable_at==0);
 } else if(!strcmp(name,"sleep-clock")) {
  global_time=5000; local_time[0]=1000; mitosis_quiescent(&task,0);
  executing=1; global_time=5100; local_time[1]=200; mitosis_runnable(&task,0);
  CHECK(taskctx.window_sleep_ns==100); CHECK(taskctx.quiescent_at==0);
 } else if(!strcmp(name,"error-running-cell")) {
  taskctx.cell=2; mitosis_dispatch(1,&task); CHECK(errors); CHECK(!refills);
 } else if(!strcmp(name,"error-running-pack")) {
  taskctx.subcell=2; mitosis_dispatch(1,&task); CHECK(errors); CHECK(!refills);
 } else if(!strcmp(name,"error-running-map")) {
  map_fail=true; mitosis_dispatch(1,&task); CHECK(errors); CHECK(!refills);
 } else if(!strcmp(name,"error-stopping-map")) {
  executing=1; map_fail=true; taskctx.runnable_at=777; mitosis_stopping(&task,true);
  CHECK(errors); CHECK(taskctx.runnable_at==777);
 } else if(!strcmp(name,"error-quiescent-pack")) {
  taskctx.runnable_at=500; taskctx.quiescent_at=777; taskctx.subcell=2; mitosis_quiescent(&task,0);
  CHECK(errors); CHECK(taskctx.quiescent_at==777); CHECK(taskctx.runnable_at==500);
 } else if(!strcmp(name,"error-quiescent-map")) {
  taskctx.runnable_at=500; taskctx.quiescent_at=777; map_fail=true; mitosis_quiescent(&task,0);
  CHECK(errors); CHECK(taskctx.quiescent_at==777); CHECK(taskctx.runnable_at==500);
 } else if(!strcmp(name,"error-running-queued")) {
  taskctx.runnable_at=500; map_fail=true; executing=1; mitosis_running(&task);
  CHECK(errors); CHECK(taskctx.running_accounted_at==1000); CHECK(taskctx.started_running_at==1000);
 } else if(!strcmp(name,"runtime-excludes-nontask")) {
  executing=1; clock_at(5000000000ULL); task_time[1]=1000;
  mitosis_running(&task);
  clock_at(5000000500ULL); task_time[1]=1350; mitosis_tick(&task);
  CHECK(cpus[1].running_ns[0]==350); CHECK(accounts[1][0].running_ns==350);
  CHECK(taskctx.running_accounted_at==1350);
 } else if(!strcmp(name,"runtime-migration")) {
  executing=1; clock_at(1000); mitosis_running(&task);
  clock_at(1200); mitosis_stopping(&task,true);
  task.cpu=0; executing=0; clock_at(1300); task_time[0]=100;
  mitosis_running(&task); CHECK(taskctx.running_accounted_at==100);
  clock_at(1350); task_time[0]=150; mitosis_stopping(&task,true);
  CHECK(cpus[1].running_ns[0]==200); CHECK(cpus[0].running_ns[0]==50);
  CHECK(accounts[1][0].running_ns==200); CHECK(accounts[0][0].running_ns==50);
 } else if(!strcmp(name,"wall-demand-window")) {
  executing=1; clock_at(1000000); task_time[1]=1000; mitosis_running(&task);
  taskctx.demand_window_at=global_time;
  clock_at(1000000+2*DEMAND_TAU_NS); task_time[1]=1200; mitosis_tick(&task);
  CHECK(taskctx.demand_window_at==global_time); CHECK(taskctx.window_run_ns==0);
 } else if(!strcmp(name,"no-wait")) {
  map_fail=true; mitosis_quiescent(&task,0); CHECK(!errors); CHECK(taskctx.quiescent_at==1500);
 } else if(!strcmp(name,"shared-accounting")) {
  executing=1; clock_at(1000); mitosis_running(&task);
  clock_at(1100); mitosis_tick(&task);
  clock_at(1150); mitosis_dispatch(1,&task);
  clock_at(1200); mitosis_stopping(&task,true);
  CHECK(!errors); CHECK(refills==1); CHECK(cpus[1].running_ns[0]==200);
  CHECK(accounts[1][0].running_ns==200); CHECK(taskctx.runnable_at==1200);
  CHECK(task.scx.dsq_vtime==200);
 } else { return 2; }
 return 0;
}
