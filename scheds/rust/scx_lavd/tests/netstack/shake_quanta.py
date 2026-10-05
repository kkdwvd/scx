#!/usr/bin/env python3
"""Share of one partition CPU between a registered spinner and a pinned
foreign spinner, measured from the processes' own CPU time in schedstat:
two shell loops pinned to the CPU, one registered. Run with lavd
--netstack [--netstack-quanta-us NET,OTHER]."""
import os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netstack as ns

def cputime(pid):
    return int(open(f'/proc/{pid}/schedstat').read().split()[0])

r = ns.request(1, [4]); g = ns.wait_grant(r['req_seq']); assert g['granted'] == [4], g
reg = subprocess.Popen(['taskset', '-c', '4', 'sh', '-c', 'while :; do :; done'])
foreign = subprocess.Popen(['taskset', '-c', '4', 'sh', '-c', 'while :; do :; done'])
time.sleep(0.2)
assert ns.register(reg.pid) == 0
time.sleep(0.3)
a = (cputime(reg.pid), cputime(foreign.pid)); time.sleep(2.0); b = (cputime(reg.pid), cputime(foreign.pid))
dr, df = b[0] - a[0], b[1] - a[1]
share = 100.0 * df / max(1, dr + df)
switches = int(open(f'/proc/{foreign.pid}/schedstat').read().split()[2])
print(f'registered {dr / 1e6:.0f} ms, foreign {df / 1e6:.0f} ms of 2000: foreign share {share:.1f}%, foreign ran {switches} times in all')
ns.register(reg.pid, False)
reg.kill(); foreign.kill(); reg.wait(); foreign.wait()
ns.request(0)
print('FOREIGN_SHARE', round(share, 1))
