#!/bin/bash
#
# Exercise scx_mitosis vtime management across the per-CPU and cell DSQs.
#
# A child cgroup of the managed parent, pinned to a cpuset, becomes a cell;
# cell 0 keeps the rest of the machine. Spinner threads inside the child are
# cell tasks, spinners started outside it and pinned with taskset are cell 0
# tasks on a foreign CPU, which is how kworkers and ksoftirqd end up on per-CPU
# DSQs in production.
# Each scenario samples /proc/<pid>/schedstat and reports CPU time and the
# longest stretch a runnable task went without running.
#
# Usage:
#   ./test_vtime_fairness.sh [--scenario NAME] [--seconds N]
#
# Scenarios (default: all but debt-abort):
#   ratchet     cell 0 task pinned to a cell CPU runs alone, then the cell
#               saturates; the pinned task should keep a fair share, not stall
#   overload    periodic cell 0 task pinned to a cell CPU while the cell holds
#               N runnable threads per CPU; reports its wakeup latency vs N
#   solo-burst  one cell task alone on a 1-CPU cell for T seconds, then a second
#               one arrives; both should get ~50% immediately
#   skew        a cell CPU idles for T seconds, then a pinned cell 0 task and
#               cell tasks compete on it; reports how long the pinned task
#               monopolises the CPU
#   debt-abort  cell 0 task pinned to an otherwise idle cell CPU runs for longer
#               than 8192 slices, then sleeps once; the scheduler must survive
#

set -u

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
PARENT="/sys/fs/cgroup/vtime-test.slice"
CGROUP="$PARENT/vt"
WORKDIR="$(mktemp -d /tmp/scx_mitosis_vtime_test.XXXXXX)"
SCHED_LOG="$WORKDIR/sched.log"
SCENARIO="all"
PHASE_S=20
EXTRA_SCHED_ARGS="${EXTRA_SCHED_ARGS:-}"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --scenario) SCENARIO="$2"; shift 2 ;;
        --seconds) PHASE_S="$2"; shift 2 ;;
        --help) head -28 "$0" | tail -25; exit 0 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

SCHED_PID=""
LOAD_PIDS=()
declare -A RESULTS

kill_load() {
    for p in "${LOAD_PIDS[@]:-}"; do [[ -n "$p" ]] && sudo kill -9 "$p" 2>/dev/null; done
    LOAD_PIDS=()
    sudo pkill -9 -x vtspin 2>/dev/null; true
}

cleanup() {
    kill_load
    if [[ -n "$SCHED_PID" ]]; then
        sudo kill -INT "$SCHED_PID" 2>/dev/null
        for _ in $(seq 1 30); do sudo kill -0 "$SCHED_PID" 2>/dev/null || break; sleep 1; done
        sudo kill -9 "$SCHED_PID" 2>/dev/null
        SCHED_PID=""
    fi
    for _ in $(seq 1 30); do [[ "$(cat /sys/kernel/sched_ext/state)" == "disabled" ]] && break; sleep 1; done
    for _ in 1 2 3 4 5; do sudo rmdir "$CGROUP" 2>/dev/null && break; sleep 0.5; done
    sudo rmdir "$PARENT" 2>/dev/null
}
trap 'cleanup; rm -rf "$WORKDIR"' EXIT

check_prerequisites() {
    [[ -x "$SCHEDULER_BIN" ]] || { log_error "Scheduler binary not found: $SCHEDULER_BIN"; exit 1; }
    for t in cc python3 taskset; do command -v $t >/dev/null || { log_error "$t not found"; exit 1; }; done
    [[ "$(cat /sys/kernel/sched_ext/state)" == "disabled" ]] || { log_error "another sched_ext scheduler is attached"; exit 1; }
    grep -qw cpuset /sys/fs/cgroup/cgroup.subtree_control || { log_error "cpuset controller not enabled at the cgroup root"; exit 1; }
    [[ -d "$PARENT" ]] && { log_error "$PARENT already exists; remove it first"; exit 1; }
}

# vtspin <threads> [busy_us sleep_us]: CPU-bound threads, or periodic ones that
# burn busy_us of thread CPU time per cycle and then sleep sleep_us.
build_spinner() {
    cat > "$WORKDIR/vtspin.c" <<'CEOF'
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static long busy_us, sleep_us;

static long thread_cpu_us(void)
{
	struct timespec t;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
	return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

static void *spin(void *arg)
{
	volatile unsigned long x = 0;

	if (!busy_us)
		for (;;)
			x++;
	for (;;) {
		long start = thread_cpu_us();
		struct timespec s = { sleep_us / 1000000, (sleep_us % 1000000) * 1000 };

		while (thread_cpu_us() - start < busy_us)
			x++;
		nanosleep(&s, NULL);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	int i, n;

	if (argc != 2 && argc != 4)
		return 2;
	n = atoi(argv[1]);
	if (argc == 4) {
		busy_us = atol(argv[2]);
		sleep_us = atol(argv[3]);
	}
	prctl(PR_SET_NAME, "vtspin", 0, 0, 0);
	if (n == 1)
		spin(NULL);
	for (i = 0; i < n; i++) {
		pthread_t t;

		if (pthread_create(&t, NULL, spin, NULL))
			return 1;
	}
	pause();
	return 0;
}
CEOF
    cc -O2 -pthread -o "$WORKDIR/vtspin" "$WORKDIR/vtspin.c" || { log_error "failed to build spinner"; exit 1; }
}

# start_scheduler CPUS: the child cgroup becomes a cell pinned to CPUS.
start_scheduler() {
    local cpus=$1
    sudo mkdir -p "$PARENT"
    grep -qw cpu /sys/fs/cgroup/cgroup.subtree_control || echo "+cpu" | sudo tee /sys/fs/cgroup/cgroup.subtree_control >/dev/null
    echo "+cpu +cpuset" | sudo tee "$PARENT/cgroup.subtree_control" >/dev/null || { log_error "failed to enable controllers on $PARENT"; exit 1; }
    sudo mkdir -p "$CGROUP"
    echo "$cpus" | sudo tee "$CGROUP/cpuset.cpus" >/dev/null || { log_error "failed to set cpuset"; exit 1; }
    # shellcheck disable=SC2086
    sudo "$SCHEDULER_BIN" --cell-parent-cgroup /vtime-test.slice $EXTRA_SCHED_ARGS >"$SCHED_LOG" 2>&1 &
    SCHED_PID=$!
    for _ in $(seq 1 240); do
        [[ "$(cat /sys/kernel/sched_ext/state)" == "enabled" ]] && { sleep 2; return 0; }
        kill -0 "$SCHED_PID" 2>/dev/null || break
        sleep 0.5
    done
    log_error "scheduler failed to attach (state: $(cat /sys/kernel/sched_ext/state))"
    sed 's/\x1b\[[0-9;]*m//g' "$SCHED_LOG" | tail -5; exit 1
}

stop_scheduler() { cleanup; }

# wait_child WRAPPER_PID: wait until the wrapper's child has become vtspin and
# echo its pid. Under overload the child may need seconds just to get its first
# run and exec; LAST_SPAWN_S records how long that took.
LAST_SPAWN_S=0
wait_child() {
    local w=$1 p="" i
    for i in $(seq 1 600); do
        p=$(pgrep -P "$w" -x vtspin | head -1); [[ -n "$p" ]] && break; sleep 0.1
    done
    LAST_SPAWN_S=$(awk "BEGIN{printf \"%.1f\", $i*0.1}")
    [[ -z "$p" ]] && p=$w
    LOAD_PIDS+=("$w" "$p"); echo "$p"
}

# cell_spin THREADS [busy sleep] -> pid of a spinner inside the cell cgroup
cell_spin() {
    sudo bash -c "echo \$\$ > $CGROUP/cgroup.procs; exec $WORKDIR/vtspin $*" >/dev/null 2>&1 &
    local w=$!; disown; wait_child "$w"
}

# root_spin CPU THREADS [busy sleep] -> pid of a cell 0 spinner pinned to CPU
root_spin() {
    local cpu=$1; shift
    sudo taskset -c "$cpu" "$WORKDIR/vtspin" "$@" >/dev/null 2>&1 &
    local w=$!; disown; wait_child "$w"
}

# sample SECONDS LABEL:PID ... -> per pid: cpu seconds, share of one CPU, longest
# runnable-without-running gap, and cumulative run delay over the window.
sample() {
    local secs=$1; shift
    sudo python3 - "$secs" "$@" <<'PY'
import sys, time
secs = float(sys.argv[1]); targets = [a.split(':') for a in sys.argv[2:]]
import os
def read(pid):
    # Aggregate over the thread group; the spinner's main thread only pauses.
    try:
        ex = dl = pc = 0; running = False
        for tid in os.listdir(f"/proc/{pid}/task"):
            e, d, c = open(f"/proc/{pid}/task/{tid}/schedstat").read().split()
            ex += int(e); dl += int(d); pc += int(c)
            st = open(f"/proc/{pid}/task/{tid}/stat").read().rsplit(')', 1)[1].split()[0]
            running = running or st == 'R'
        return ex, dl, pc, 'R' if running else 'S'
    except (FileNotFoundError, ProcessLookupError):
        return None
start = {}; last = {}; gap = {}; maxgap = {}
for label, pid in targets:
    s = read(pid); start[label] = s; last[label] = s; gap[label] = 0.0; maxgap[label] = 0.0
t0 = time.time(); dt = 0.25
while time.time() - t0 < secs:
    time.sleep(dt)
    for label, pid in targets:
        s = read(pid)
        if s is None or last[label] is None: continue
        if s[0] == last[label][0] and s[3] == 'R':
            gap[label] += dt; maxgap[label] = max(maxgap[label], gap[label])
        else:
            gap[label] = 0.0
        last[label] = s
print(f"{'task':<14}{'cpu s':>8}{'share':>8}{'max gap s':>11}{'delay s':>9}  comm")
for label, pid in targets:
    a, b = start[label], last[label]
    if a is None or b is None: print(f"{label:<14}{'gone':>8}"); continue
    cpu = (b[0]-a[0])/1e9; delay = (b[1]-a[1])/1e9
    try: comm = open(f"/proc/{pid}/comm").read().strip()
    except OSError: comm = "?"
    print(f"{label:<14}{cpu:8.2f}{cpu/secs:8.2f}{maxgap[label]:11.2f}{delay:9.2f}  {comm}")
PY
}

sched_alive() { [[ "$(cat /sys/kernel/sched_ext/state)" == "enabled" ]]; }
stall_seen() { sudo dmesg | tail -50 | grep -q 'runnable task stall'; }

record() { # NAME PASS|FAIL detail
    RESULTS[$1]=$2; if [[ $2 == PASS ]]; then log_info "$1: PASS $3"; else log_error "$1: FAIL $3"; fi
}

scenario_ratchet() {
    log_info "ratchet: cell vt=0-7; cell 0 spinner pinned to CPU 3 alone for ${PHASE_S}s, then 32 cell threads"
    start_scheduler 0-7; sudo dmesg -C
    local pinned; pinned=$(root_spin 3 1)
    sleep "$PHASE_S"
    local cell; cell=$(cell_spin 32)
    log_info "ratchet: phase B, sampling ${PHASE_S}s"
    local out; out=$(sample "$PHASE_S" pinned:$pinned cell:$cell); echo "$out" | sed 's/^/    /'
    local share gap; share=$(echo "$out" | awk '$1=="pinned"{print $3}'); gap=$(echo "$out" | awk '$1=="pinned"{print $4}')
    stop_scheduler
    # 32 threads on 8 CPUs plus the pinned task: fair share on CPU 3 is 1/5.
    if awk "BEGIN{exit !($share >= 0.10 && $gap < 5)}"; then record ratchet PASS "pinned share $share, max gap ${gap}s"; else record ratchet FAIL "pinned share $share (fair ~0.20), max gap ${gap}s"; fi
}

scenario_overload() {
    local n
    for n in 25 100 200; do
        log_info "overload: cell vt=0-7 with $n threads/CPU; periodic cell 0 task (1ms/50ms) pinned to CPU 3"
        start_scheduler 0-7; sudo dmesg -C
        local cell; cell=$(cell_spin $((n*8)))
        sleep 3
        local pinned; pinned=$(root_spin 3 1 1000 50000); local spawn=$LAST_SPAWN_S
        log_info "overload n=$n: pinned task needed ${spawn}s to get its first run and exec"
        local out; out=$(sample "$PHASE_S" pinned:$pinned); echo "$out" | sed 's/^/    /'
        local gap; gap=$(echo "$out" | awk '$1=="pinned"{print $4}')
        local expected; expected=$(awk "BEGIN{printf \"%.1f\", $n*0.02}")
        log_info "overload n=$n: max wakeup gap ${gap}s, first-run latency ${spawn}s (one full round of the cell queue is ~${expected}s)"
        stop_scheduler
        record "overload-$n" "$(awk "BEGIN{print ($gap < 1.0 && $spawn < 1.0) ? \"PASS\" : \"FAIL\"}")" "max wakeup gap ${gap}s, first-run latency ${spawn}s"
    done
}

scenario_solo_burst() {
    log_info "solo-burst: 1-CPU cell (CPU 3); one cell spinner alone for ${PHASE_S}s, then a second one"
    start_scheduler 3; sudo dmesg -C
    local a; a=$(cell_spin 1)
    sleep "$PHASE_S"
    local b; b=$(cell_spin 1)
    log_info "solo-burst: phase B, sampling ${PHASE_S}s"
    local out; out=$(sample "$PHASE_S" first:$a second:$b); echo "$out" | sed 's/^/    /'
    local sa gap; sa=$(echo "$out" | awk '$1=="first"{print $3}'); gap=$(echo "$out" | awk '$1=="first"{print $4}')
    stop_scheduler
    if awk "BEGIN{exit !($sa >= 0.35 && $gap < 3)}"; then record solo-burst PASS "first task share $sa, max gap ${gap}s"; else record solo-burst FAIL "first task share $sa (fair 0.50), max gap ${gap}s"; fi
}

scenario_skew() {
    log_info "skew: 2-CPU cell (2-3); 3 cell threads for ${PHASE_S}s so one CPU runs a lone extended task, then a pinned cell 0 task joins that CPU"
    start_scheduler 2-3; sudo dmesg -C
    local a; a=$(cell_spin 3)
    sleep "$PHASE_S"
    # The CPU hosting exactly one of the three threads has had no stopping()
    # calls, so its clock is frozen while the other CPU advanced the cell's.
    local solo_cpu; solo_cpu=$(for t in /proc/$a/task/*; do awk '{print $39}' $t/stat; done | sort | uniq -c | awk '$1==1{print $2}' | head -1)
    [[ -z "$solo_cpu" ]] && solo_cpu=3
    local pinned; pinned=$(root_spin "$solo_cpu" 1)
    log_info "skew: pinned cell 0 task on CPU $solo_cpu (frozen clock), sampling ${PHASE_S}s"
    local out; out=$(sample "$PHASE_S" pinned:$pinned cell3:$a); echo "$out" | sed 's/^/    /'
    local share; share=$(echo "$out" | awk '$1=="pinned"{print $3}')
    stop_scheduler
    # 4 runnable tasks on 2 CPUs; the pinned task's fair share of its CPU is ~0.5.
    if awk "BEGIN{exit !($share <= 0.70)}"; then record skew PASS "pinned share $share"; else record skew FAIL "pinned task monopolised its CPU: share $share (fair ~0.50)"; fi
}

scenario_debt_abort() {
    local run_s=$(( ${DEBT_SLICES:-8192} * 20 / 1000 + 10 ))
    log_info "debt-abort: cell 0 spinner pinned to idle cell CPU 3 for ${run_s}s (>${DEBT_SLICES:-8192} slices), then made to sleep once"
    start_scheduler 0-7; sudo dmesg -C
    local pinned; pinned=$(root_spin 3 1)
    sleep "$run_s"
    # Wake it into a busy CPU so it goes through enqueue(); an idle CPU would
    # let select_cpu() dispatch it straight to the local DSQ instead.
    local cell; cell=$(cell_spin 16); sleep 1
    sudo kill -STOP "$pinned"; sleep 1; sudo kill -CONT "$pinned"; sleep 3
    if sched_alive; then record debt-abort PASS "scheduler survived a $run_s s cross-cell pinned run"; else record debt-abort FAIL "scheduler exited: $(sed 's/\x1b\[[0-9;]*m//g' "$SCHED_LOG" | grep -m1 -o 'vtime too far ahead[^"]*' || echo see log)"; fi
    stop_scheduler
}

check_prerequisites
build_spinner
case $SCENARIO in
    ratchet) scenario_ratchet ;;
    overload) scenario_overload ;;
    solo-burst) scenario_solo_burst ;;
    skew) scenario_skew ;;
    debt-abort) scenario_debt_abort ;;
    all) scenario_ratchet; scenario_solo_burst; scenario_skew; scenario_overload ;;
    *) log_error "unknown scenario $SCENARIO"; exit 1 ;;
esac
echo; log_info "Results:"; failed=0
for name in "${!RESULTS[@]}"; do if [[ ${RESULTS[$name]} == PASS ]]; then echo -e "  ${GREEN}PASS${NC} $name"; else echo -e "  ${RED}FAIL${NC} $name"; failed=1; fi; done
stall_seen && log_warn "dmesg reports a runnable task stall during this run"
exit $failed
