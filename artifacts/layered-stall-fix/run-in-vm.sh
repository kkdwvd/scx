#!/bin/bash
# Runs inside the VM: run-in-vm.sh <scx_layered binary> <label> <secs> [layered args...]
set -u
D=$(dirname "$(readlink -f "$0")")
BIN=$1; LABEL=$2; SECS=$3; shift 3
LOG=$D/out/$LABEL.layered.log
mkdir -p "$D/out"

echo "=== $LABEL: $(uname -r), $(nproc) cpus, layered args: $*"
"$BIN" --stats 5 "$@" "f:$D/drain.json" >"$LOG" 2>&1 &
LPID=$!

for i in $(seq 1 100); do
	[ "$(cat /sys/kernel/sched_ext/state)" = enabled ] && break
	sleep 0.2
done
if [ "$(cat /sys/kernel/sched_ext/state)" != enabled ]; then
	echo "scheduler did not attach"; tail -20 "$LOG"; exit 1
fi
sleep 2

"$D/drainwl" 8 1 "$SECS" | tee "$D/out/$LABEL.wl.log" | grep -E "RESULT|t=( 5|10|20|30|40|50|60)"

if kill -0 $LPID 2>/dev/null; then
	echo "SCHED: still attached at the end ($(cat /sys/kernel/sched_ext/state))"
	kill -INT $LPID; wait $LPID
else
	wait $LPID
	echo "SCHED: exited during the run, status $?"
fi
grep -E "runnable task stall|EXIT:|Error:|stall" "$LOG" | head -5
echo "--- drain stats (last report)"
awk '/^ *drn /{blk=""; on=1} on{blk=blk $0 "\n"} /^ *rest /{on=0} END{printf "%s", blk}' "$LOG" | head -14
