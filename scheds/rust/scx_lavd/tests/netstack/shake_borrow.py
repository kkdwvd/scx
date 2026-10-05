#!/usr/bin/env python3
"""Gated borrowing: run with lavd --netstack --netstack-borrow
--netstack-borrow-after-ms 200. Other tasks may use a granted CPU only
after its registered threads have left it idle for the settling time, and
leave again when a registered thread takes it or the pool is exclusive."""
import os, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netstack as ns

fails = 0
def check(name, ok, detail=''):
    global fails
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

def busy(cpus, dt=0.5):
    def read():
        d = {}
        for l in open('/proc/stat'):
            if l.startswith('cpu') and not l.startswith('cpu '):
                f = l.split(); v = list(map(int, f[1:])); d[int(f[0][3:])] = (sum(v), v[3] + v[4])
        return d
    a = read(); time.sleep(dt); b = read()
    return {c: round(100 * (1 - (b[c][1] - a[c][1]) / max(1, b[c][0] - a[c][0]))) for c in cpus}

class Spinner(threading.Thread):
    def __init__(self, duty=1.0):
        super().__init__(daemon=True); self.tid = 0; self.stop = False; self.duty = duty
    def run(self):
        self.tid = threading.get_native_id()
        while not self.stop:
            t = time.monotonic()
            while time.monotonic() - t < 0.001 * self.duty:
                pass
            if self.duty < 1.0:
                time.sleep(0.001 * (1 - self.duty))
def start(duty=1.0):
    s = Spinner(duty); s.start()
    while not s.tid:
        time.sleep(0.001)
    return s

def grant(target, cands=None, flags_exclusive=False):
    if flags_exclusive:
        import struct
        data = struct.pack('<IiIIQ', 0, target, ns.REQ_CANDIDATES | 4, 0, 0)
        data += struct.pack(f'<{ns.WORDS}Q', *ns.mask_words(cands)) + bytes(16 * ns.WORDS)
        ret, raw = ns.run('request_capacity', data); assert ret >= 0, ret
        seq = struct.unpack_from('<Q', raw, 16)[0]
        return ns.wait_grant(seq)
    r = ns.request(target, cands); assert r['ret'] >= 0, r
    return ns.wait_grant(r['req_seq'])

ncpu = os.cpu_count()
hogs = [subprocess.Popen(['sh', '-c', 'while :; do :; done']) for _ in range(ncpu + 2)]
import atexit; atexit.register(lambda: [h.kill() for h in hogs])
time.sleep(0.3)

g = grant(2, [4, 5])
b = busy([4, 5], 0.15)
check('granted CPUs idle before the gate opens', max(b.values()) < 50, f'{b}')
time.sleep(0.4)
b = busy([4, 5])
check('hogs borrow idle granted CPUs after the settling time', min(b.values()) > 50, f'{b}')

sp = start(1.0); assert ns.register(sp.tid) == 0
time.sleep(0.3)
cpu = int(open(f'/proc/{os.getpid()}/task/{sp.tid}/stat').read().rsplit(')', 1)[1].split()[36])
other = 5 if cpu == 4 else 4
b = busy([4, 5])
# The spinner's CPU is 100% busy either way; the question is who runs there.
on = {}
for _ in range(40):
    for h in hogs:
        try:
            c = int(open(f'/proc/{h.pid}/stat').read().rsplit(')', 1)[1].split()[36]); on[c] = on.get(c, 0) + 1
        except OSError:
            pass
    time.sleep(0.02)
check('registered spinner shuts the gate on its CPU', on.get(cpu, 0) == 0, f'spinner on {cpu}, hog samples {dict(sorted(on.items()))}')
check('the other granted CPU still borrowed', on.get(other, 0) > 0, f'{dict(sorted(on.items()))}')

sp.stop = True; sp.join(); ns.register(sp.tid, False)
g = grant(2, [4, 5], flags_exclusive=True)
time.sleep(0.5)
b = busy([4, 5])
check('exclusive pool is never borrowed', max(b.values()) < 50, f'{b}')

lo = start(0.3); assert ns.register(lo.tid) == 0   # 30% duty: under the threshold
g = grant(2, [4, 5])
time.sleep(0.6)
b = busy([4, 5])
check('a lightly loaded registered CPU is borrowed', min(b.values()) > 50, f'{b}')
lo.stop = True; lo.join(); ns.register(lo.tid, False)
grant(0)
print('FAILS', fails)
