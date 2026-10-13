#!/bin/bash
# Verify that a bursty, low-utilization subcell is sized for its bursts while
# its cell has slack, and that the headroom tapers off as the cell fills.
#
# One configured cell pinned to 8 cores of a single LLC holds three subcells:
# "bursty" (4 workers that spin 500 ms every 2 s: 1 CPU mean, 4 CPUs peak),
# "steady" (workers spinning continuously) and the catch-all "rest".
#
# With 3 steady workers the cell has slack in every window. The scheduler
# runs twice: sized by smoothed demand alone (--util-quantile 0) and sized
# for the p90 of CPU usage over 100 ms windows (the default). Sized by
# demand, bursty gets 2 CPUs and runs half of every burst on borrowed CPUs;
# sized for the p90 it gets 4 and borrows nothing.
#
# With 6 steady workers the cell is full whenever bursty bursts, so about a
# quarter of the windows have no slack. The p90 run must then measure that
# slack and size bursty between its demand and its p90.

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
CGROUP_BASE="/sys/fs/cgroup/test.slice"
CGROUP="$CGROUP_BASE/burst_headroom"
WORK_DIR="$(mktemp -d /tmp/scx_mitosis_burst.XXXXXX)"
CONFIG="$WORK_DIR/cells.json"
RUN_SECS="${RUN_SECS:-24}"
SETTLE_SECS="${SETTLE_SECS:-10}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi
if [[ ! -x "$SCHEDULER_BIN" ]]; then
    echo -e "${RED}Scheduler binary not found: $SCHEDULER_BIN${NC}"
    echo -e "${RED}Please build with: cargo build --release -p scx_mitosis${NC}"
    exit 1
fi
if [[ ! -f "/sys/kernel/sched_ext/state" ]]; then
    echo -e "${RED}sched_ext not available (missing /sys/kernel/sched_ext/state)${NC}"
    exit 1
fi
if [[ "$(cat /sys/kernel/sched_ext/state)" != "disabled" ]]; then
    echo -e "${RED}another sched_ext scheduler is already running${NC}"
    exit 1
fi

# Eight CPUs sharing CPU 0's last-level cache, one per core.
mapfile -t LLC_CPUS < <(python3 - <<'PY'
def expand(s):
    out = []
    for part in s.strip().split(","):
        a, _, b = part.partition("-")
        out.extend(range(int(a), int(b or a) + 1))
    return out
try:
    llc = expand(open("/sys/devices/system/cpu/cpu0/cache/index3/shared_cpu_list").read())
except FileNotFoundError:
    # No cache topology (a VM, typically): treat every CPU as one LLC.
    llc = expand(open("/sys/devices/system/cpu/online").read())
seen, cores = set(), []
for cpu in llc:
    sibs = expand(open(f"/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list").read())
    key = tuple(sorted(sibs))
    if key in seen:
        continue
    seen.add(key)
    cores.append(cpu)
for cpu in cores[:8]:
    print(cpu)
PY
)
if (( ${#LLC_CPUS[@]} < 4 )); then
    echo -e "${RED}Need at least 4 cores in one LLC, found ${#LLC_CPUS[@]}${NC}"
    exit 1
fi
CELL_CPUS=$(IFS=,; echo "${LLC_CPUS[*]}")
NR_CELL_CPUS=${#LLC_CPUS[@]}
if (( $(nproc) <= NR_CELL_CPUS )); then
    echo -e "${RED}Need more CPUs than the ${NR_CELL_CPUS} given to the cell${NC}"
    exit 1
fi

WORKER_PIDS=()
SCHED_PID=""
MONITOR_PID=""

stop_workers() {
    for pid in "${WORKER_PIDS[@]:-}"; do
        [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
    done
    WORKER_PIDS=()
}

stop_scheduler() {
    [[ -n "$MONITOR_PID" ]] && kill "$MONITOR_PID" 2>/dev/null || true
    [[ -n "$SCHED_PID" ]] && kill -INT "$SCHED_PID" 2>/dev/null || true
    if [[ -n "$SCHED_PID" ]]; then
        for _ in $(seq 1 40); do
            ps -p "$SCHED_PID" > /dev/null 2>&1 || break
            sleep 0.25
        done
        kill -9 "$SCHED_PID" 2>/dev/null || true
    fi
    SCHED_PID=""
    MONITOR_PID=""
}

cleanup() {
    echo -e "\n${YELLOW}Cleanup...${NC}"
    stop_workers
    stop_scheduler
    pkill -9 -f "$WORK_DIR/" 2>/dev/null || true
    if [[ -d "$CGROUP" ]]; then
        while read -r pid; do
            [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
        done < <(cat "$CGROUP/cgroup.procs" 2>/dev/null || true)
        rmdir "$CGROUP" 2>/dev/null || true
    fi
    rmdir "$CGROUP_BASE" 2>/dev/null || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}SUBCELL BURST HEADROOM TEST${NC}"
echo -e "${YELLOW}========================================${NC}\n"
echo "cell CPUs: $CELL_CPUS"

mkdir -p "$CGROUP_BASE"
for ctrl in cpu cpuset; do
    if ! grep -qw "$ctrl" "$CGROUP_BASE/cgroup.subtree_control" 2>/dev/null; then
        grep -qw "$ctrl" /sys/fs/cgroup/cgroup.subtree_control || echo "+$ctrl" > /sys/fs/cgroup/cgroup.subtree_control
        echo "+$ctrl" > "$CGROUP_BASE/cgroup.subtree_control"
    fi
done
mkdir -p "$CGROUP"
echo "$CELL_CPUS" > "$CGROUP/cpuset.cpus"

cat > "$CONFIG" <<JSON
[
  {
    "name": "burst_headroom",
    "matches": { "CgroupContains": "burst_headroom" },
    "subcells": [
      { "name": "bursty", "matches": [[{ "CommPrefix": "burstwrk" }]] },
      { "name": "steady", "matches": [[{ "CommPrefix": "stedywrk" }]] },
      { "name": "rest", "matches": [[]] }
    ]
  }
]
JSON

# Workers exec python3 through symlinks so their comm is the symlink name.
ln -s "$(command -v python3)" "$WORK_DIR/burstwrk"
ln -s "$(command -v python3)" "$WORK_DIR/stedywrk"
cat > "$WORK_DIR/burst.py" <<'PY'
import sys, time
period, duty = float(sys.argv[1]), float(sys.argv[2])
# All burst workers share the monotonic clock, so their bursts line up.
while True:
    phase = time.monotonic() % period
    if phase < duty:
        end = time.monotonic() + (duty - phase)
        while time.monotonic() < end:
            pass
    else:
        time.sleep(period - phase)
PY
cat > "$WORK_DIR/steady.py" <<'PY'
while True:
    pass
PY

# Tasks are matched into subcells by comm when they enter the cell, so each
# worker is started first, given time to exec, and only then moved into the
# cgroup; otherwise it would be matched as "bash" into the catch-all subcell
# until the next configuration refresh.
start_workers() {
    local steady=$1 i pid
    for i in 1 2 3 4; do
        "$WORK_DIR/burstwrk" "$WORK_DIR/burst.py" 2 0.5 &
        WORKER_PIDS+=("$!")
    done
    for i in $(seq 1 "$steady"); do
        "$WORK_DIR/stedywrk" "$WORK_DIR/steady.py" &
        WORKER_PIDS+=("$!")
    done
    sleep 0.5
    for pid in "${WORKER_PIDS[@]}"; do
        echo "$pid" > "$CGROUP/cgroup.procs"
    done
}

# run_mode <label> <quantile> <steady workers>: run the scheduler with the
# workers for RUN_SECS and leave the monitor output in $WORK_DIR/<label>.json.
run_mode() {
    local label=$1 quantile=$2 steady=$3
    local log="$WORK_DIR/$label.log" monitor="$WORK_DIR/$label.json"

    echo -e "\n${YELLOW}Running mode '$label' (--util-quantile $quantile, $steady steady workers) for ${RUN_SECS}s${NC}"
    "$SCHEDULER_BIN" --cell-config "$CONFIG" \
        --enable-rebalancing \
        --reconfiguration-interval-s 2 \
        --rebalance-cooldown-s 2 \
        --util-quantile "$quantile" \
        > "$log" 2>&1 &
    SCHED_PID=$!
    for _ in $(seq 1 120); do
        [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" == "enabled" ]] && break
        ps -p "$SCHED_PID" > /dev/null 2>&1 || break
        sleep 0.5
    done
    if ! ps -p "$SCHED_PID" > /dev/null 2>&1 || [[ "$(cat /sys/kernel/sched_ext/state)" != "enabled" ]]; then
        echo -e "${RED}scx_mitosis failed to start${NC}"
        cat "$log"
        exit 1
    fi

    start_workers "$steady"
    "$SCHEDULER_BIN" --monitor 1 > "$monitor" 2>/dev/null &
    MONITOR_PID=$!
    sleep "$RUN_SECS"

    stop_workers
    stop_scheduler
    sleep 1
}

run_mode demand 0 3
run_mode p90 0.9 3
run_mode full 0.9 6

python3 - "$WORK_DIR/demand.json" "$WORK_DIR/p90.json" "$WORK_DIR/full.json" "$SETTLE_SECS" <<'PY'
import json, statistics, sys

def samples(path):
    text = open(path).read()
    decoder, pos, out = json.JSONDecoder(), 0, []
    while pos < len(text):
        while pos < len(text) and text[pos] in " \t\r\n":
            pos += 1
        if pos >= len(text):
            break
        try:
            obj, pos = decoder.raw_decode(text, pos)
        except json.JSONDecodeError:
            break
        out.append(obj)
    return out

def burst_cell_entry(sample):
    """The cell whose subcells include "bursty"; cell 0 has its own "rest"."""
    for cell in sample.get("cells", {}).values():
        subs = {sub.get("name"): sub for sub in cell.get("subcells", {}).values()}
        if "bursty" in subs:
            return cell, subs
    return {}, {}

def burst_cell(sample):
    return burst_cell_entry(sample)[1]

def timeline(label, rows):
    print(f"\n{label}: per-sample CPUs (bursty/steady/rest), bursty borrow%, bursty need")
    line = []
    for i, r in enumerate(rows):
        subs = burst_cell(r)
        if not subs or "bursty" not in subs:
            line.append(f"{i:>2}:-")
            continue
        cpus = "/".join(str(subs[n]["num_cpus"]) if n in subs else "-" for n in ("bursty", "steady", "rest"))
        line.append(f"{i:>2}:{cpus} {subs['bursty']['demand_borrow_pct']:.0f}% {subs['bursty'].get('need', 0.0):.1f}")
    for k in range(0, len(line), 6):
        print("  " + "  ".join(line[k:k + 6]))

def summarize(path, label, settle):
    rows = samples(path)
    if len(rows) <= settle:
        print(f"{path}: only {len(rows)} monitor samples", file=sys.stderr)
        sys.exit(1)
    timeline(label, rows)
    rows = rows[settle:]
    out = {
        "slack": statistics.mean(
            burst_cell_entry(r)[0].get("slack_fraction", 1.0) for r in rows if burst_cell(r)
        )
    }
    for name in ("bursty", "steady", "rest"):
        subs = [s for s in (burst_cell(r).get(name) for r in rows) if s]
        if not subs:
            print(f"{path}: subcell {name} missing from monitor output", file=sys.stderr)
            sys.exit(1)
        out[name] = {
            "cpus": statistics.median(s["num_cpus"] for s in subs),
            "borrow_pct": statistics.mean(s["demand_borrow_pct"] for s in subs),
            "demand": statistics.mean(s["smoothed_demand"] for s in subs),
            "util_q": statistics.mean(s.get("util_quantile", 0.0) for s in subs),
            "need": statistics.mean(s.get("need", 0.0) for s in subs),
        }
    return out

settle = int(sys.argv[4])
demand = summarize(sys.argv[1], "demand", settle)
p90 = summarize(sys.argv[2], "p90", settle)
full = summarize(sys.argv[3], "full", settle)

print(f"\n{'mode':6s} {'subcell':8s} {'cpus':>5s} {'borrow%':>8s} {'demand':>7s} {'util_q':>7s} {'need':>6s} {'slack':>6s}")
for label, res in (("demand", demand), ("p90", p90), ("full", full)):
    for name in ("bursty", "steady", "rest"):
        r = res[name]
        print(f"{label:6s} {name:8s} {r['cpus']:5.0f} {r['borrow_pct']:8.1f} {r['demand']:7.2f} {r['util_q']:7.2f} {r['need']:6.2f} {res['slack']:6.2f}")

ok = True
if p90["bursty"]["cpus"] < demand["bursty"]["cpus"] + 1:
    print("FAIL: quantile sizing did not give the bursty subcell more CPUs", file=sys.stderr)
    ok = False
if p90["bursty"]["borrow_pct"] >= demand["bursty"]["borrow_pct"]:
    print("FAIL: quantile sizing did not reduce the bursty subcell's borrowing", file=sys.stderr)
    ok = False
if p90["slack"] < 0.95:
    print(f"FAIL: cell with slack in every window measured slack {p90['slack']:.2f}", file=sys.stderr)
    ok = False
if not 0.4 <= full["slack"] <= 0.9:
    print(f"FAIL: cell full during bursts measured slack {full['slack']:.2f}", file=sys.stderr)
    ok = False
b = full["bursty"]
if not b["demand"] + 0.1 < b["need"] < b["util_q"] - 0.1:
    print(f"FAIL: full cell did not taper bursty's need ({b['demand']:.2f} < {b['need']:.2f} < {b['util_q']:.2f})", file=sys.stderr)
    ok = False
sys.exit(0 if ok else 1)
PY

echo -e "\n${GREEN}PASS${NC}: bursty subcell is sized for its usage quantile while the cell has slack"
