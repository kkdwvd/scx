#!/bin/bash
# batch.sh <runs per variant> <workload secs> <variant>...
# Boots one VM per run, all in parallel, and prints one summary line per run.
S=$(dirname "$(readlink -f "$0")")
TOP=$(dirname "$S")
K=$1; SECS=$2; WL=$3; LARGS=$4; shift 4
mkdir -p "$S/out"

for v in "$@"; do
	for i in $(seq 1 "$K"); do
		label=$v-$i
		( cd "$S" && script -qfec "timeout $((SECS + 150)) vng -r $S/vmlinuz --cpus 16 --memory 4G \
			--qemu-opts='-smp 16,sockets=4,cores=4,threads=1' --rwdir=$TOP -- \
			$S/run-in-vm2.sh $S/layered.$v $label $SECS $WL $LARGS" /dev/null \
			> "$S/out/$label.vm.log" 2>&1 ) &
	done
done
wait

for v in "$@"; do
	for i in $(seq 1 "$K"); do
		label=$v-$i
		res=$(grep -a RESULT "$S/out/$label.vm.log" | tr -d '\r' | tail -1)
		stall=$(sed 's/\x1b\[[0-9;]*m//g' "$S/out/$label.layered.log" | grep -a -m1 -o "runnable task stall.*")
		drain=$(sed 's/\x1b\[[0-9;]*m//g' "$S/out/$label.layered.log" | grep -a -o "llc_drain/try=[0-9./]*" | sort -t= -k2 -rn | head -1)
		echo "$label: ${res:-NO RESULT} | max ${drain:-no stats} | ${stall:-no stall}"
	done
done
