#!/usr/bin/env python3
"""Exhaustive interleaving check of scx_layered's LLC drain interlock.

Shared state: Q (tasks on the kernel DSQ), N (tasks counted by the
scheduler), C (layer has CPUs on the LLC), D (drain bit). Every shared access
is one atomic step and steps interleave arbitrarily (sequential consistency).

Threads:
  enqueue  ops.enqueue() for one task, then the kernel queueing it after the
           callback returns
  drain    one try_drain_layer_node_llcs() pass over the LLC, then
           ops.running() for the task it consumed, if any
  refresh  userspace clears nr_llc_cpus, then refresh_cpumasks() runs

A completed schedule is bad if a task is left on the DSQ of an LLC without
CPUs with draining off: Q > 0 and not C and not D.

A thread is a function (pc, local, shared) -> (pc, local, shared) that runs
one atomic step. pc None means the thread is finished. Schedules are counted
by memoizing on the global state.
"""
import sys
from functools import lru_cache

Q, N, C, D = range(4)


def upd(s, i, v):
    return s[:i] + (v,) + s[i + 1:]


def enqueue(fixed):
    def step(pc, loc, s):
        if pc == 'inc':                      # atomic nr_queued increment
            return 'readc', loc, upd(s, N, s[N] + 1)
        if pc == 'readc':                    # after scx_bpf_dsq_insert()
            return ('land' if s[C] else 'setd'), loc, s
        if pc == 'setd':                     # layer_llc_drain_enable()
            return 'land', loc, upd(s, D, True)
        if pc == 'land':                     # callback returned, task queued
            return None, loc, upd(s, Q, s[Q] + 1)
    return ('inc' if fixed else 'readc'), step


def drain(fixed):
    nr = N if fixed else Q

    def step(pc, loc, s):
        disabled, consumed = loc
        if pc == 'testd':                    # llcs_to_drain test
            return ('testc' if s[D] else None), loc, s
        if pc == 'testc':                    # nr_llc_cpus test
            return (None if s[C] else 'readn'), loc, s
        if pc == 'readn':                    # current: <= 1 on the DSQ
            off = s[nr] == 0 if fixed else s[nr] <= 1
            return ('clrd' if off else 'consume'), loc, s
        if pc == 'clrd':                     # layer_llc_drain_disable()
            return 'consume', (True, consumed), upd(s, D, False)
        if pc == 'consume':                  # scx_bpf_dsq_move_to_local()
            if s[Q] > 0:
                consumed, s = True, upd(s, Q, s[Q] - 1)
            nxt = 'recheck' if disabled else 'running'
            if nxt == 'running' and not (consumed and fixed):
                nxt = None
            return nxt, (disabled, consumed), s
        if pc == 'recheck':
            nxt = 'setd' if s[nr] else 'running'
            if nxt == 'running' and not (consumed and fixed):
                nxt = None
            return nxt, loc, s
        if pc == 'setd':                     # re-enable
            nxt = 'running' if consumed and fixed else None
            return nxt, loc, upd(s, D, True)
        if pc == 'running':                  # ops.running() uncharges
            return None, loc, upd(s, N, s[N] - 1)
    return 'testd', step


def refresh(fixed):
    nr = N if fixed else Q

    def step(pc, loc, s):
        if pc == 'wrc':                      # userspace shrinks the layer
            return 'rdc', loc, upd(s, C, False)
        if pc == 'rdc':                      # after the cpus_seq atomic
            return ('clrd' if s[C] else 'rdn'), loc, s
        if pc == 'clrd':
            return None, loc, upd(s, D, False)
        if pc == 'rdn':
            return ('setd' if s[nr] else None), loc, s
        if pc == 'setd':
            return None, loc, upd(s, D, True)
    return 'wrc', step


def explore(threads, init):
    steps = [t[1] for t in threads]

    @lru_cache(maxsize=None)
    def count(s, ts):
        """(schedules, bad schedules) from this global state."""
        live = [i for i, (pc, _) in enumerate(ts) if pc is not None]
        if not live:
            return 1, int(s[Q] > 0 and not s[C] and not s[D])
        total = bad = 0
        for i in live:
            pc, loc = ts[i]
            npc, nloc, ns = steps[i](pc, loc, s)
            t, b = count(ns, ts[:i] + ((npc, nloc),) + ts[i + 1:])
            total += t
            bad += b
        return total, bad

    return count(init, tuple((t[0], (False, False)) for t in threads))


def queued(n):
    """LLC without CPUs, draining on, n tasks already queued."""
    return lambda fixed: (n, n if fixed else 0, False, True)


def covered(fixed):
    """Layer still has CPUs on the LLC, nothing queued."""
    return (0, 0, True, False)


E, Dr, R = enqueue, drain, refresh
SCENARIOS = [
    ('enqueue vs drain, one task queued', [E, Dr], queued(1)),
    ('enqueue vs drain, empty DSQ', [E, Dr], queued(0)),
    ('enqueue vs 2 drains', [E, Dr, Dr], queued(1)),
    ('2 enqueues vs drain', [E, E, Dr], queued(0)),
    ('2 enqueues vs 3 drains', [E, E, Dr, Dr, Dr], queued(1)),
    ('3 enqueues vs 3 drains', [E, E, E, Dr, Dr, Dr], queued(2)),
    ('enqueue vs refresh', [E, R], covered),
    ('enqueue vs refresh vs drain', [E, R, Dr], covered),
    ('2 enqueues vs refresh vs 2 drains', [E, E, R, Dr, Dr], covered),
]

sys.setrecursionlimit(10000)
rc = 0
for name, threads, init in SCENARIOS:
    for fixed in (False, True):
        total, bad = explore([t(fixed) for t in threads], init(fixed))
        tag = 'fixed  ' if fixed else 'current'
        print(f'{name:34s} {tag}: {total:16d} schedules, {bad:15d} bad')
        if fixed and bad:
            rc = 1
sys.exit(rc)
