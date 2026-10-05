#!/usr/bin/env python3
"""Yield: with the application side saturated, lavd withholds CPUs from a
pool whose registered threads leave them mostly idle, one per settling
interval, and gives them back once the application calms down. Run with
lavd --netstack --netstack-yield --netstack-yield-after-ms 300."""
import os, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netstack as ns

fails = 0
def check(name, ok, detail=''):
    global fails
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

class Duty(threading.Thread):
    def __init__(self, duty):
        super().__init__(daemon=True); self.tid = 0; self.stop = False; self.duty = duty
    def run(self):
        self.tid = threading.get_native_id()
        while not self.stop:
            t = time.monotonic()
            while time.monotonic() - t < 0.001 * self.duty:
                pass
            time.sleep(0.001 * (1 - self.duty))
def start(duty):
    s = Duty(duty); s.start()
    while not s.tid:
        time.sleep(0.001)
    return s

def trace(seconds, step=0.1):
    out = []
    t = time.monotonic()
    while time.monotonic() - t < seconds:
        out.append(ns.get()['nr_granted']); time.sleep(step)
    return out

ncpu = os.cpu_count()
r = ns.request(2, [6, 7]); g = ns.wait_grant(r['req_seq']); assert g['nr_granted'] == 2, g
lo = start(0.3); assert ns.register(lo.tid) == 0      # a lightly loaded poller
time.sleep(0.5)
check('idle application: nothing withheld', ns.get()['nr_granted'] == 2)

hogs = [subprocess.Popen(['sh', '-c', 'while :; do :; done']) for _ in range(ncpu + 2)]
import atexit; atexit.register(lambda: [h.kill() for h in hogs])
tr = trace(1.5)
check('saturated application: CPUs withheld step by step', tr[-1] < 2 and tr[0] >= tr[-1], f'{tr}')
g = ns.get()
print('   grant now', g['granted'], 'target', g['target'])
# The pool's own demand returns while the application stays saturated:
# two registered spinners, as processes, want the CPUs back.
lo.stop = True; lo.join(); ns.register(lo.tid, False)
sps = [subprocess.Popen(['sh', '-c', 'while :; do :; done']) for _ in range(2)]
time.sleep(0.1)
for p_ in sps:
    assert ns.register(p_.pid) == 0
tr = trace(2.0)
check('pool in demand: CPUs given back under a saturated application', tr[-1] == 2, f'{tr}')
for p_ in sps:
    ns.register(p_.pid, False); p_.kill()
for p_ in sps:
    p_.wait()
lo = start(0.3); assert ns.register(lo.tid) == 0
tr = trace(1.5)
check('demand gone, application still saturated: withheld again', tr[-1] < 2, f'{tr}')
for h in hogs:
    h.kill()
for h in hogs:
    h.wait()
hogs.clear()
tr = trace(1.5)
check('application calm: CPUs given back', tr[-1] == 2, f'{tr}')
lo.stop = True; lo.join(); ns.register(lo.tid, False)
ns.request(0)
print('FAILS', fails)
