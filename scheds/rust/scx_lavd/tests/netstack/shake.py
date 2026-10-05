#!/usr/bin/env python3
"""Shake-out of scx_lavd's netstack partition inside the kdev guest: run with
lavd already up. Prints one line per check, PASS or FAIL."""
import json, os, subprocess, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netstack as ns

BPFTOOL = os.environ.get('BPFTOOL', 'bpftool')
NCPU = os.cpu_count()
fails = 0

def check(name, ok, detail=''):
    global fails
    fails += not ok
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

def where(pid, tid=None):
    p = f'/proc/{pid}/task/{tid}/stat' if tid else f'/proc/{pid}/stat'
    return int(open(p).read().rsplit(')', 1)[1].split()[36])

def samples(targets, n=40, dt=0.025):
    out = {k: {} for k in targets}
    for _ in range(n):
        for k, (pid, tid) in targets.items():
            try:
                c = where(pid, tid); out[k][c] = out[k].get(c, 0) + 1
            except OSError:
                pass
        time.sleep(dt)
    return {k: dict(sorted(v.items())) for k, v in out.items()}

def hogs(n):
    return [subprocess.Popen(['sh', '-c', 'while :; do :; done']) for _ in range(n)]

def grant(target, candidates=None, drop=None):
    r = ns.request(target, candidates, drop)
    assert r['ret'] >= 0, r
    g = ns.wait_grant(r['req_seq'])
    assert g['req_seq'] >= r['req_seq'], (r, g)
    return g

def cpu_ctx():
    out = subprocess.run([BPFTOOL, '-j', 'map', 'dump', 'name', 'cpu_ctx_stor'],
                         capture_output=True, text=True).stdout
    try:
        d = json.loads(out)
    except json.JSONDecodeError:
        return None
    # A percpu map: find every per-CPU value, whatever the nesting.
    found = []
    def walk(x, cpu=None):
        if isinstance(x, dict):
            if 'value' in x and isinstance(x['value'], dict) and 'nr_pinned_tasks' in x['value']:
                v = x['value']
                found.append((x.get('cpu', cpu), v['nr_pinned_tasks'], v['nr_foreign_pinned'], v['netstack']))
            else:
                for k, y in x.items():
                    walk(y, x.get('cpu', cpu))
        elif isinstance(x, list):
            for y in x:
                walk(y, cpu)
    walk(d)
    return found or None

class Spinner(threading.Thread):
    def __init__(self, cpus=None):
        super().__init__(daemon=True); self.tid = 0; self.n = 0; self.stop = False; self.cpus = cpus
    def run(self):
        self.tid = threading.get_native_id()
        if self.cpus is not None:
            os.sched_setaffinity(0, self.cpus)
        while not self.stop:
            self.n += 1

def start(spinner):
    spinner.start()
    while not spinner.tid:
        time.sleep(0.001)
    return spinner

me = os.getpid()
H = hogs(NCPU + 2)
import atexit
atexit.register(lambda: [h.kill() for h in H])
time.sleep(0.3)

# 1. Grow and shrink cycles under load.
t0 = time.monotonic(); seqs = 0
for i in range(60):
    tgt = [1, 2, 3, 4, 2, 0][i % 6]
    g = grant(tgt, candidates=[4, 5, 6, 7])
    if g['nr_granted'] != min(tgt, 4):
        check('cycle grant size', False, f'{tgt} -> {g}'); break
    seqs += 1
check('60 grow/shrink cycles', seqs == 60, f'in {time.monotonic() - t0:.2f}s')

# 2. Hogs off the partition after many cycles; evict path.
g = grant(3, candidates=[4, 5, 6, 7])
time.sleep(0.05)
BORROW = os.environ.get('NETSTACK_BORROW') == '1'   # idle partition CPUs may then carry other tasks
for rep in range(3):
    s = samples({'hogs%d' % i: (h.pid, None) for i, h in enumerate(H)}, n=20)
    on_part = sum(v.get(c, 0) for v in s.values() for c in g['granted'])
    if BORROW:
        print(f'INFO hogs on granted CPUs under borrowing (pass {rep}): {on_part} samples'); continue
    check(f'hogs off granted CPUs (pass {rep})', on_part == 0, f'granted {g["granted"]} on-partition samples {on_part}')
    if on_part:
        print('   hog placement:', {k: v for k, v in s.items() if set(v) & set(g['granted'])})
        cc = cpu_ctx()
        print('   cpu_ctx (cpu, pinned, foreign, netstack):', [c for c in (cc or []) if c[0] in g['granted']])
    time.sleep(0.3)

# 3. Four registered spinners on a 2-CPU partition all progress: separate
#    processes, since threads of one Python process share its lock.
def cputime(pid):
    return int(open(f'/proc/{pid}/schedstat').read().split()[0])
g = grant(2, candidates=[4, 5])
sp = [subprocess.Popen(['sh', '-c', 'while :; do :; done']) for _ in range(4)]
time.sleep(0.1)
for s_ in sp:
    assert ns.register(s_.pid) == 0
time.sleep(0.3)
n0 = [cputime(s_.pid) for s_ in sp]; time.sleep(1.0); n1 = [cputime(s_.pid) for s_ in sp]
prog = [round((b - a) / 1e6) for a, b in zip(n0, n1)]
s = samples({f'sp{i}': (s_.pid, None) for i, s_ in enumerate(sp)}, n=20)
off = sum(v.get(c, 0) for v in s.values() for c in range(NCPU) if c not in g['granted'])
check('4 registered on {4,5} share and progress', min(prog) > 100 and off == 0,
      f'ms of CPU in 1 s {prog} placement {s}')
for s_ in sp:
    s_.kill()
for s_ in sp:
    s_.wait()

# 4. The sync-wakeup leak path: a registered thread ping-pongs with an
#    unregistered one over a pipe; the partner must stay off the partition.
r1, w1 = os.pipe(); r2, w2 = os.pipe()
state = {'a': 0, 'b': 0, 'stop': False}
def ping():
    state['a'] = threading.get_native_id()
    while not state['stop']:
        os.write(w1, b'x'); os.read(r2, 1)
def pong():
    state['b'] = threading.get_native_id()
    while not state['stop']:
        os.read(r1, 1); os.write(w2, b'y')
ta = threading.Thread(target=ping, daemon=True); tb = threading.Thread(target=pong, daemon=True)
ta.start(); tb.start()
while not (state['a'] and state['b']):
    time.sleep(0.001)
assert ns.register(state['a']) == 0
time.sleep(0.2)
s = samples({'reg': (me, state['a']), 'partner': (me, state['b'])}, n=80, dt=0.01)
leak = sum(s['partner'].get(c, 0) for c in g['granted'])
inside = sum(s['reg'].get(c, 0) for c in g['granted'])
if BORROW:
    print(f'INFO sync-wake partner under borrowing: {s}')
else:
    check('sync-wake partner stays off partition', leak == 0, f'{s}')
check('registered ping thread on partition', inside >= 0.9 * sum(s['reg'].values()), f'{s["reg"]}')
state['stop'] = True; os.write(w1, b'x'); os.write(w2, b'y'); ta.join(1); tb.join(1)

# 5. A registered thread whose affinity excludes the partition still runs.
sx = start(Spinner(cpus={0, 1}))
assert ns.register(sx.tid) == 0
time.sleep(0.2); a = sx.n; time.sleep(0.5); b = sx.n
s = samples({'sx': (me, sx.tid)}, n=10)
check('registered thread pinned outside partition runs', b > a and set(s['sx']) <= {0, 1}, f'{s}')
sx.stop = True; sx.join()

# 6. Foreign pinned task on a partition CPU progresses beside a registered
#    spinner on the same CPU (a process each; the share is measured by quanta).
g = grant(1, candidates=[4])
sp = subprocess.Popen(['taskset', '-c', '4', 'sh', '-c', 'while :; do :; done'])
fp = subprocess.Popen(['taskset', '-c', '4', 'sh', '-c', 'while :; do :; done'])
time.sleep(0.1); assert ns.register(sp.pid) == 0
time.sleep(0.2); a = cputime(fp.pid); time.sleep(1.0); b = cputime(fp.pid)
check('pinned foreign task progresses beside a registered spinner', b - a > 20_000_000, f'{(b - a) / 1e6:.0f} ms of CPU in 1 s')
ns.register(sp.pid, False)
sp.kill(); fp.kill(); sp.wait(); fp.wait()
g = grant(2, candidates=[4, 5])

# 7. Invalid and edge requests.
r = ns.request(1, candidates=[])          # candidates flag with an empty mask
g = ns.wait_grant(r['req_seq'])
check('empty candidates grants nothing', g['nr_granted'] == 0, f'{g}')
g = grant(NCPU + 100, candidates=list(range(NCPU)))
check('target beyond cap is capped', g['nr_granted'] == g['cap'] and g['cap'] < NCPU, f'{g}')
ret, _ = ns.run('request_capacity', bytes(24 + 3 * 8 * ns.WORDS))  # domain 0, target 0, flags 0: valid
check('zero request accepted', ret >= 0, f'ret {ret}')
import struct
bad = struct.pack('<IiIIQ', 200, 0, 0, 0, 0) + bytes(3 * 8 * ns.WORDS)
ret, _ = ns.run('request_capacity', bad)
check('unknown pool rejected', ret == -22, f'ret {ret}')
bad = struct.pack('<IiIIQ', 0, 0, 0x100, 0, 0) + bytes(3 * 8 * ns.WORDS)
ret, _ = ns.run('request_capacity', bad)
check('reserved flag rejected', ret == -22, f'ret {ret}')
check('register unknown tid', ns.register(999999) == -3, '')

# 8. Concurrent requesters: no corruption, final grant consistent.
res = []
def req(n):
    for i in range(30):
        res.append(ns.request((i + n) % 4, candidates=[4, 5, 6, 7])['ret'])
ts = [threading.Thread(target=req, args=(k,)) for k in range(3)]
[t.start() for t in ts]; [t.join() for t in ts]
busy = sum(1 for r in res if r == -16)
time.sleep(0.05)
g = ns.get()
check('concurrent requesters', all(r >= 0 or r == -16 for r in res) and (g['req_seq'] % 2 == 0),
      f'{busy} busy of {len(res)}, final {g}')

# 9. Hotplug a granted CPU.
g = grant(2, candidates=[4, 5])
try:
    open('/sys/devices/system/cpu/cpu5/online', 'w').write('0')
    time.sleep(0.1)
    g2 = ns.get()
    open('/sys/devices/system/cpu/cpu5/online', 'w').write('1')
    time.sleep(0.1)
    g3 = grant(2, candidates=[4, 5])
    check('offline CPU leaves the grant and returns', g2['granted'] == [4] and g3['granted'] == [4, 5],
          f'offline {g2["granted"]} back {g3["granted"]}')
except OSError as e:
    check('hotplug', False, str(e))

# 10. Release everything; counters settle.
g = grant(0)
for h in H:
    h.kill()
for h in H:
    h.wait()
time.sleep(0.3)
cc = cpu_ctx()
if cc is None:
    check('cpu_ctx counters readable', False, 'bpftool dump failed')
else:
    bad = [c for c in cc if c[1] != 0 or c[2] != 0 or c[3] != 0]
    check('pinned counters and marks back to zero', not bad, f'{bad[:4]}')
print('FAILS', fails)
