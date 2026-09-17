#!/bin/bash
#
# Test load-weighted subcell partitioning in scx_mitosis --cell-config mode.
#
# A cgroup pinned to a small cpuset becomes a configured cell with two named
# subcells matched by comm prefix plus the catch-all "rest" subcell. Spinner
# threads with the matching names load the two subcells unevenly and the
# test checks that the CPU split follows the per-subcell load reported in
# the stats, both below saturation and once both subcells are saturated,
# where utilization alone cannot tell them apart.
#
# Usage:
#   ./test_subcell_load_partition.sh [--scenario NAME] [--cpus LIST] [--seconds N]
#
# Scenarios (default: all):
#   saturated    24 heavy vs 6 light threads on 8 CPUs, expect 5:2:1
#   mirrored     6 heavy vs 24 light threads, expect 2:5:1
#   unsaturated  3 heavy vs 1 light threads, expect 5:2:1
#   zero         8 heavy vs 0 light threads, expect light at its 1-CPU floor
#   swap         saturated, then the two thread counts swapped mid-run
#   dutycycle    40 heavy threads at 1/8 duty (5 CPUs of work) vs 6 CPU-bound
#                light threads (6 CPUs), both saturated; demand must
#                give light more CPUs (3:4:1) although heavy has more threads
#

set -u

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
CGROUP="/sys/fs/cgroup/subcell-load-test.slice"
WORKDIR="$(mktemp -d /tmp/scx_mitosis_subcell_test.XXXXXX)"
STATS_LOG="$WORKDIR/stats.log"
CPUS="0-7"
SECONDS_PER_PHASE=25
SCENARIO="all"
REFRESH_S=2

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --scenario) SCENARIO="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --seconds) SECONDS_PER_PHASE="$2"; shift 2 ;;
        --help) head -24 "$0" | tail -21; exit 0 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

SCHED_PID=""
declare -A RESULTS

cleanup() {
    sudo pkill -9 -x ldheavy 2>/dev/null
    sudo pkill -9 -x ldlight 2>/dev/null
    if [[ -n "$SCHED_PID" ]]; then
        # The scheduler runs as root: check liveness as root too, then wait for
        # sched_ext to report the teardown complete before anything else starts.
        sudo kill -INT "$SCHED_PID" 2>/dev/null
        for _ in $(seq 1 30); do sudo kill -0 "$SCHED_PID" 2>/dev/null || break; sleep 1; done
        sudo kill -9 "$SCHED_PID" 2>/dev/null
        SCHED_PID=""
    fi
    for _ in $(seq 1 30); do [[ "$(cat /sys/kernel/sched_ext/state)" == "disabled" ]] && break; sleep 1; done
    for _ in 1 2 3 4 5; do sudo rmdir "$CGROUP" 2>/dev/null && break; sleep 0.5; done
}
trap 'cleanup; rm -rf "$WORKDIR"' EXIT

check_prerequisites() {
    [[ -x "$SCHEDULER_BIN" ]] || { log_error "Scheduler binary not found: $SCHEDULER_BIN"; exit 1; }
    command -v cc >/dev/null || { log_error "cc not found"; exit 1; }
    command -v python3 >/dev/null || { log_error "python3 not found"; exit 1; }
    [[ "$(cat /sys/kernel/sched_ext/state)" == "disabled" ]] || { log_error "another sched_ext scheduler is attached"; exit 1; }
    grep -qw cpuset /sys/fs/cgroup/cgroup.subtree_control || { log_error "cpuset controller not enabled at the cgroup root"; exit 1; }
}

# Threads whose comm is the given name, so CommPrefix rules can route them
# into subcells. Without a duty cycle they spin forever; with one they burn
# busy_us of CPU time per cycle, measured on the thread clock so contention
# stretches the cycle but not the work, then sleep sleep_us.
build_spinner() {
    cat > "$WORKDIR/spin.c" <<'CEOF'
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

struct cfg {
	const char *name;
	long busy_us;
	long sleep_us;
};

static long thread_cpu_us(void)
{
	struct timespec t;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
	return t.tv_sec * 1000000L + t.tv_nsec / 1000;
}

static void *spin(void *arg)
{
	struct cfg *c = arg;
	volatile unsigned long x = 0;

	prctl(PR_SET_NAME, c->name, 0, 0, 0);
	if (!c->busy_us)
		for (;;)
			x++;
	for (;;) {
		long start = thread_cpu_us();
		struct timespec s = { c->sleep_us / 1000000, (c->sleep_us % 1000000) * 1000 };

		while (thread_cpu_us() - start < c->busy_us)
			x++;
		nanosleep(&s, NULL);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	static struct cfg c;
	int i, n;

	if (argc != 3 && argc != 5)
		return 2;
	c.name = argv[1];
	n = atoi(argv[2]);
	if (argc == 5) {
		c.busy_us = atol(argv[3]);
		c.sleep_us = atol(argv[4]);
	}
	prctl(PR_SET_NAME, argv[1], 0, 0, 0);
	for (i = 0; i < n; i++) {
		pthread_t t;

		if (pthread_create(&t, NULL, spin, &c))
			return 1;
	}
	pause();
	return 0;
}
CEOF
    cc -O2 -pthread -o "$WORKDIR/spin" "$WORKDIR/spin.c" || { log_error "failed to build spinner"; exit 1; }
}

write_config() {
    cat > "$WORKDIR/cells.json" <<JSON
[
  { "name": "loadtest", "matches": { "CgroupContains": "subcell-load-test.slice" },
    "subcells": [
      { "name": "heavy", "matches": [[{ "CommPrefix": "ldheavy" }]] },
      { "name": "light", "matches": [[{ "CommPrefix": "ldlight" }]] },
      { "name": "rest",  "matches": [[]] } ] },
  { "name": "rest", "matches": {} }
]
JSON
}

start_scheduler() {
    sudo mkdir -p "$CGROUP"
    echo "$CPUS" | sudo tee "$CGROUP/cpuset.cpus" >/dev/null || { log_error "failed to set cpuset"; exit 1; }
    # Tracing logs and the --monitor-sync JSON both go to stdout.
    sudo "$SCHEDULER_BIN" --cell-config "$WORKDIR/cells.json" --enable-rebalancing \
        --reconfiguration-interval-s "$REFRESH_S" --monitor-sync 1 >"$STATS_LOG" 2>&1 &
    SCHED_PID=$!
    for _ in $(seq 1 240); do
        [[ "$(cat /sys/kernel/sched_ext/state)" == "enabled" ]] && return 0
        kill -0 "$SCHED_PID" 2>/dev/null || break
        sleep 0.5
    done
    log_error "scheduler failed to attach (sched_ext state: $(cat /sys/kernel/sched_ext/state))"
    sed 's/\x1b\[[0-9;]*m//g' "$STATS_LOG" | tail -5; exit 1
}

stop_scheduler() { cleanup; }

# start_load HEAVY LIGHT [HEAVY_BUSY_US HEAVY_SLEEP_US]
start_load() {
    local heavy=$1 light=$2 duty="${3:-} ${4:-}"
    sudo pkill -9 -x ldheavy 2>/dev/null; sudo pkill -9 -x ldlight 2>/dev/null
    if [[ "$heavy" -gt 0 ]]; then
        sudo bash -c "echo \$\$ > $CGROUP/cgroup.procs; exec $WORKDIR/spin ldheavy $heavy $duty" & disown
    fi
    if [[ "$light" -gt 0 ]]; then
        sudo bash -c "echo \$\$ > $CGROUP/cgroup.procs; exec $WORKDIR/spin ldlight $light" & disown
    fi
    sleep 0.5
}

# Print "heavy_cpus light_cpus rest_cpus heavy_demand light_demand" for the most
# common split over the last $1 samples of the current stats log, plus the
# per-sample table on stderr.
summarize() {
    python3 - "$STATS_LOG" "$1" <<'PY'
import json, sys
from collections import Counter
txt = open(sys.argv[1]).read(); last_n = int(sys.argv[2])
dec = json.JSONDecoder(); i = 0; rows = []
while True:
    j = txt.find('{', i)
    if j < 0: break
    try: obj, k = dec.raw_decode(txt, j)
    except json.JSONDecodeError: i = j + 1; continue
    i = k
    if not isinstance(obj, dict) or 'cells' not in obj: continue
    for cid, c in obj['cells'].items():
        subs = {s['name']: s for s in c.get('subcells', {}).values()}
        if {'heavy', 'light', 'rest'} <= set(subs):
            rows.append(tuple(subs[n]['num_cpus'] for n in ('heavy', 'light', 'rest'))
                        + tuple(subs[n]['demand'] for n in ('heavy', 'light'))
                        + tuple(subs[n]['load'] for n in ('heavy', 'light')))
print("  t  heavy light rest | demand heavy light | runnable heavy light", file=sys.stderr)
for t, r in enumerate(rows):
    print(f"{t:>3} {r[0]:>6} {r[1]:>5} {r[2]:>4} | {r[3]:9.2f} {r[4]:5.2f} | {r[5]:9.2f} {r[6]:5.2f}", file=sys.stderr)
tail = rows[-last_n:]
split = Counter(r[:3] for r in tail).most_common(1)[0][0]
print(*split, f"{sum(r[3] for r in tail)/len(tail):.2f}", f"{sum(r[4] for r in tail)/len(tail):.2f}")
PY
}

# assert_split NAME EXPECTED_HEAVY EXPECTED_LIGHT: pass when the dominant
# split over the last 8 samples matches, allowing one CPU of slack on each
# side but never letting the ordering of the two flip.
assert_split() {
    local name=$1 want_h=$2 want_l=$3 ordered=1
    read -r h l r lh ll < <(summarize 8 2>"$WORKDIR/$name.table")
    [[ -n "${KEEP_STATS_DIR:-}" ]] && cp "$STATS_LOG" "$KEEP_STATS_DIR/$name.stats" && cp "$WORKDIR/$name.table" "$KEEP_STATS_DIR/$name.table"
    log_info "$name: dominant split heavy=$h light=$l rest=$r (demand heavy=$lh light=$ll)"
    if (( want_h < want_l && h >= l )) || (( want_h > want_l && h <= l )); then ordered=0; fi
    if (( ordered && h >= want_h - 1 && h <= want_h + 1 && l >= want_l - 1 && l <= want_l + 1 )); then
        RESULTS[$name]=PASS
    else
        RESULTS[$name]=FAIL
        log_error "$name: expected heavy~$want_h light~$want_l"
        cat "$WORKDIR/$name.table"
    fi
}

# run_scenario NAME HEAVY LIGHT WANT_HEAVY WANT_LIGHT [HEAVY_BUSY_US HEAVY_SLEEP_US]
run_scenario() {
    local name=$1 heavy=$2 light=$3 want_h=$4 want_l=$5
    log_info "Scenario $name: heavy=$heavy light=$light threads on CPUs $CPUS for ${SECONDS_PER_PHASE}s"
    : > "$STATS_LOG"
    start_scheduler
    start_load "$heavy" "$light" "${6:-}" "${7:-}"
    sleep "$SECONDS_PER_PHASE"
    assert_split "$name" "$want_h" "$want_l"
    stop_scheduler
}

run_swap() {
    log_info "Scenario swap: 24 heavy vs 6 light, then 6 heavy vs 24 light"
    : > "$STATS_LOG"
    start_scheduler
    start_load 24 6
    sleep "$SECONDS_PER_PHASE"
    assert_split swap-before 5 2
    : > "$STATS_LOG"
    start_load 6 24
    sleep "$SECONDS_PER_PHASE"
    assert_split swap-after 2 5
    stop_scheduler
}

check_prerequisites
build_spinner
write_config

# Expected splits assume 8 CPUs: every subcell keeps a 1-CPU floor and the
# remaining 5 are split by load, so 4:1 gives 5:2:1 and 0 load gives the floor.
case $SCENARIO in
    saturated)   run_scenario saturated 24 6 5 2 ;;
    mirrored)    run_scenario mirrored 6 24 2 5 ;;
    unsaturated) run_scenario unsaturated 3 1 5 2 ;;
    zero)        run_scenario zero 8 0 6 1 ;;
    swap)        run_swap ;;
    dutycycle)   run_scenario dutycycle 40 6 3 4 1000 7000 ;;
    all)
        run_scenario saturated 24 6 5 2
        run_scenario mirrored 6 24 2 5
        run_scenario unsaturated 3 1 5 2
        run_scenario zero 8 0 6 1
        run_scenario dutycycle 40 6 3 4 1000 7000
        run_swap
        ;;
    *) log_error "unknown scenario $SCENARIO"; exit 1 ;;
esac

echo; log_info "Results:"
failed=0
for name in "${!RESULTS[@]}"; do
    if [[ ${RESULTS[$name]} == PASS ]]; then echo -e "  ${GREEN}PASS${NC} $name"; else echo -e "  ${RED}FAIL${NC} $name"; failed=1; fi
done
exit $failed
