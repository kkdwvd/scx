#!/usr/bin/env python3
"""Pools: a domain pool and the global pool sharing the cap, threads of
each on their own pool's CPUs. Run inside the guest with lavd up."""
import os, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netstack as ns

fails = 0
def check(name, ok, detail=''):
    global fails
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

def where(tid):
    return int(open(f'/proc/{os.getpid()}/task/{tid}/stat').read().rsplit(')', 1)[1].split()[36])

def sample(tid, n=30):
    on = {}
    for _ in range(n):
        c = where(tid); on[c] = on.get(c, 0) + 1
        time.sleep(0.02)
    return dict(sorted(on.items()))

class Spinner(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True); self.tid = 0; self.stop = False
    def run(self):
        self.tid = threading.get_native_id()
        while not self.stop:
            pass
def start():
    s = Spinner(); s.start()
    while not s.tid:
        time.sleep(0.001)
    return s

def grant(target, pool, cands=None):
    r = ns.request(target, cands, pool=pool); assert r['ret'] >= 0, r
    g = ns.wait_grant(r['req_seq'], pool=pool); assert g['req_seq'] >= r['req_seq'], (r, g)
    return g

npools = 1
while ns.get(pool=npools)['ret'] != -22 and npools < 130:
    npools += 1
print('pools:', npools)
g1 = grant(2, 1)
check('domain pool 1 granted 2', g1['nr_granted'] == 2, f'{g1}')
r = ns.get(pool=npools)
check('pool beyond the domains rejected', r['ret'] == -22, f'{r["ret"]}')
g0 = grant(3, 0)
check('global pool capped by what pool 1 holds', g0['nr_granted'] == 2 and not set(g0['granted']) & set(g1['granted']),
      f'pool0 {g0["granted"]} pool1 {g1["granted"]} cap {g0["cap"]}')
s1 = start(); s0 = start()
check('register to pool 1', ns.register(s1.tid, pool=1) == 0)
check('register to pool 0', ns.register(s0.tid, pool=0) == 0)
check('re-register to another pool refused', ns.register(s1.tid, pool=0) == -17)
time.sleep(0.2)
p1 = sample(s1.tid); p0 = sample(s0.tid)
check('pool 1 thread on pool 1 CPUs', set(p1) <= set(g1['granted']), f'{p1} in {g1["granted"]}')
check('global thread on any granted CPU', set(p0) <= set(g0['granted']) | set(g1['granted']), f'{p0}')
g1 = grant(0, 1)
time.sleep(0.05)
g0 = grant(4, 0)
check('pool 1 released, global pool takes its room', g1['nr_granted'] == 0 and g0['nr_granted'] == 4, f'{g0}')
time.sleep(0.2)
p1 = sample(s1.tid)
check('pool 1 thread without a grant runs somewhere', sum(p1.values()) == 30, f'{p1}')
ns.register(s1.tid, False); ns.register(s0.tid, False)
s1.stop = True; s0.stop = True; s1.join(); s0.join()
grant(0, 0)
print('FAILS', fails)
