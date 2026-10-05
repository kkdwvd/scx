#!/bin/sh
# Integration tests of scx_lavd's network soft partition. Run as root on a
# sched_ext kernel with bpffs mounted; the tests start scx_lavd themselves.
#
#   LAVD=path/to/scx_lavd [BPFTOOL=path/to/bpftool] [SUITES="..."] ./run.sh
#
# Suites: battery (the general checks, in performance mode and under
# autopilot, and under --per-cpu-dsq and --warm-cpu-us), pools, borrow,
# quanta (prints the pinned task's share at several settings), yield.
# Each suite's checks print PASS or FAIL; the script exits nonzero if any
# failed or scx_lavd did not come up.
set -u
T=$(cd "$(dirname "$0")" && pwd)
LAVD=${LAVD:-scx_lavd}
OUT=${OUT:-/tmp/scx_lavd-netstack}
mkdir -p "$OUT"
rc=0

start_lavd() {
	$LAVD --netstack --netstack-max-cpus 4 "$@" > "$OUT/lavd.log" 2>&1 &
	LPID=$!
	for i in $(seq 1 100); do
		[ "$(cat /sys/kernel/sched_ext/state)" = enabled ] && return 0
		kill -0 $LPID 2>/dev/null || break
		sleep 0.1
	done
	echo "FAIL scx_lavd did not come up with: $*"; tail -20 "$OUT/lavd.log"; rc=1; return 1
}
stop_lavd() {
	kill -INT $LPID 2>/dev/null; wait $LPID 2>/dev/null
	grep -iE "error|stall" "$OUT/lavd.log" | tail -3
}
run_py() {
	python3 -u "$T/$1" || rc=1
}

for suite in ${SUITES:-battery pools borrow quanta yield}; do
	case $suite in
	battery)
		for extra in "--performance" "" "--performance --per-cpu-dsq" "--performance --warm-cpu-us 200"; do
			echo "=== battery $extra"
			start_lavd $extra || continue
			run_py shake.py; stop_lavd
		done ;;
	pools)
		echo "=== pools"; start_lavd --performance || continue
		run_py shake_pools.py; stop_lavd ;;
	borrow)
		echo "=== borrow"; start_lavd --performance --netstack-borrow --netstack-borrow-after-ms 200 || continue
		run_py shake_borrow.py; NETSTACK_BORROW=1 run_py shake.py; stop_lavd ;;
	quanta)
		for q in "0,0" "4000,1000" "800,200" "80,20" "50,50"; do
			echo "=== quanta $q"; start_lavd --performance --netstack-quanta-us $q || continue
			run_py shake_quanta.py; stop_lavd
		done ;;
	yield)
		echo "=== yield"; start_lavd --performance --netstack-yield --netstack-yield-after-ms 300 || continue
		run_py shake_yield.py; stop_lavd ;;
	*) echo "unknown suite $suite"; rc=1 ;;
	esac
done
dmesg | grep -iE "sched_ext.*(BUG|WARNING|stall)" | tail -4
exit $rc
