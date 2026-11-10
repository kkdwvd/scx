#!/bin/bash
# summary.sh <label prefix>...: one line per run found in out/
S=$(dirname "$(readlink -f "$0")")
for v in "$@"; do
	for f in $(ls "$S"/out/$v-*.vm.log 2>/dev/null | sort -V); do
		label=$(basename "$f" .vm.log)
		res=$(grep -a RESULT "$f" | tr -d '\r' | tail -1)
		clean=$(sed 's/\x1b\[[0-9;]*m//g' "$S/out/$label.layered.log")
		stall=$(echo "$clean" | grep -a -m1 -o "runnable task stall.*")
		drain=$(echo "$clean" | grep -a -o "llc_drain/try=[0-9.]*/[0-9.]*" | awk -F'[=/]' '$4+0 > m {m=$4+0; l=$0} END{print l}')
		echo "$label: ${res:-NO RESULT} | peak ${drain:-no drain stats} | ${stall:-no stall}"
	done
done
