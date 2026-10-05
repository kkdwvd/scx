#!/usr/bin/env python3
"""A client of scx_lavd's netstack programs through bpf(2): BPF_OBJ_GET on
the pinned program, BPF_PROG_TEST_RUN with the argument struct as ctx_in,
which the kernel copies back with the program's outputs."""
import ctypes, os, struct, sys, time

libc = ctypes.CDLL(None, use_errno=True)
SYS_bpf = 321
BPF_OBJ_GET, BPF_PROG_TEST_RUN = 7, 10
DIR = os.environ.get('NETSTACK_DIR', '/sys/fs/bpf/scx_lavd/netstack')
WORDS = 128
REQ_CANDIDATES, REQ_DROP = 1, 2


class ObjGet(ctypes.Structure):
    _fields_ = [('pathname', ctypes.c_uint64), ('bpf_fd', ctypes.c_uint32),
                ('file_flags', ctypes.c_uint32)]


class TestRun(ctypes.Structure):
    _fields_ = [('prog_fd', ctypes.c_uint32), ('retval', ctypes.c_uint32),
                ('data_size_in', ctypes.c_uint32), ('data_size_out', ctypes.c_uint32),
                ('data_in', ctypes.c_uint64), ('data_out', ctypes.c_uint64),
                ('repeat', ctypes.c_uint32), ('duration', ctypes.c_uint32),
                ('ctx_size_in', ctypes.c_uint32), ('ctx_size_out', ctypes.c_uint32),
                ('ctx_in', ctypes.c_uint64), ('ctx_out', ctypes.c_uint64),
                ('flags', ctypes.c_uint32), ('cpu', ctypes.c_uint32),
                ('batch_size', ctypes.c_uint32)]


def bpf(cmd, attr):
    r = libc.syscall(SYS_bpf, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


def run(name, data):
    path = ctypes.create_string_buffer(f'{DIR}/{name}'.encode())
    fd = bpf(BPF_OBJ_GET, ObjGet(pathname=ctypes.addressof(path)))
    buf = ctypes.create_string_buffer(data, len(data))
    attr = TestRun(prog_fd=fd, ctx_size_in=len(data), ctx_in=ctypes.addressof(buf))
    try:
        bpf(BPF_PROG_TEST_RUN, attr)
    finally:
        os.close(fd)
    return ctypes.c_int32(attr.retval).value, buf.raw


def mask_words(cpus):
    w = [0] * WORDS
    for c in cpus:
        w[c // 64] |= 1 << (c % 64)
    return w


def mask_cpus(words):
    return [i * 64 + b for i, w in enumerate(words) for b in range(64) if w >> b & 1]


def register(tid=0, on=True, pool=0):
    ret, _ = run('register_thread' if on else 'unregister_thread', struct.pack('<iIII', tid, 0, pool, 0))
    return ret


def get(pool=0):
    ret, raw = run('get_capacity', struct.pack('<I', pool) + bytes(12 + 16 + 8 * WORDS))
    domain, nr, target, cap, req_seq, grant_seq = struct.unpack_from('<IIIIQQ', raw)
    granted = mask_cpus(struct.unpack_from(f'<{WORDS}Q', raw, 32))
    return {'ret': ret, 'nr_granted': nr, 'target': target, 'cap': cap,
            'req_seq': req_seq, 'grant_seq': grant_seq, 'granted': granted}


def request(target, candidates=None, drop=None, pool=0):
    flags = (REQ_CANDIDATES if candidates is not None else 0) | (REQ_DROP if drop is not None else 0)
    data = struct.pack('<IiIIQ', pool, target, flags, 0, 0)
    data += struct.pack(f'<{WORDS}Q', *mask_words(candidates or []))
    data += struct.pack(f'<{WORDS}Q', *mask_words(drop or []))
    data += bytes(8 * WORDS)
    ret, raw = run('request_capacity', data)
    _, _, _, nr, req_seq = struct.unpack_from('<IiIIQ', raw)
    return {'ret': ret, 'prev_granted': nr, 'req_seq': req_seq}


def wait_grant(req_seq, timeout=1.0, pool=0):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
        g = get(pool)
        if g['req_seq'] >= req_seq:
            return g
        time.sleep(0.005)
    return get(pool)


def cpulist(s):
    out = []
    for part in s.split(','):
        if '-' in part:
            a, b = map(int, part.split('-'))
            out += range(a, b + 1)
        elif part:
            out.append(int(part))
    return out


if __name__ == '__main__':
    cmd = sys.argv[1]
    if cmd == 'get':
        print(get())
    elif cmd in ('register', 'unregister'):
        print(register(int(sys.argv[2]) if len(sys.argv) > 2 else 0, cmd == 'register'))
    elif cmd == 'request':
        cands = cpulist(sys.argv[3]) if len(sys.argv) > 3 else None
        r = request(int(sys.argv[2]), cands)
        print(r, wait_grant(r['req_seq']))
