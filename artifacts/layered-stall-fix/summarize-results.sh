#!/bin/bash
# summarize-results.sh <results dir>: one line per run, then totals.
# A run "stalled" if the watchdog aborted the scheduler. A run has a "gap" if
# the workload saw a thread go unscheduled for over a second (drainwl2 only).
D=$1
strip() { sed 's/\x1b\[[0-9;]*m//g' "$1"; }
for v in unfixed fixed; do
	n=0; stalls=0; gaps=0
	for f in $(ls "$D"/$v-*.vm.log 2>/dev/null | sort -V); do
		l=$(basename "$f" .vm.log)
		res=$(grep -a RESULT "$f" | tr -d '\r' | tail -1 | sed 's/^RESULT //')
		stall=$(strip "$D/$l.layered.log" | grep -a -m1 -o "runnable task stall.*")
		dsq=$(strip "$D/$l.layered.log" | grep -a -E "LAYER\[0\]\(drn\)-DSQ\[[0-9]+\] .*nr_queued=[1-9]" |
			awk '{print $1, $3, $4}' | paste -sd';')
		mask=$(strip "$D/$l.layered.log" | grep -a -m1 -o "LAYER\[0\](drn) CPUS=[0-9a-f]*")
		anti=$(strip "$D/$l.layered.log" | grep -a -o 'antistall=[0-9]*' |
			awk -F'=' '$2+0>m{m=$2+0} END{print m+0}')
		n=$((n + 1))
		[ -n "$stall" ] && stalls=$((stalls + 1))
		echo "$res" | grep -q 'gaps(>1s)=[1-9]' && gaps=$((gaps + 1))
		echo "$l: $res | antistall=$anti | ${stall:-no watchdog abort}${dsq:+ | $dsq}${mask:+ | $mask}"
	done
	[ $n -gt 0 ] && echo "TOTAL $v: $n runs, $stalls watchdog aborts, $gaps runs with a gap over 1s"
done
