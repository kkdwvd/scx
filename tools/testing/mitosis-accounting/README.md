# scx_mitosis accounting regression harness

This host harness reproduces the CPU-context, timestamp-domain, and error
propagation concerns in PR #3817. It runs the scheduler's extracted callback
and accounting helper bodies against mocked clocks, per-CPU maps, and injected
lookup errors. It requires Python 3 and a C compiler; no root access or running
sched_ext scheduler is needed.

Run from any directory:

```sh
python3 tools/testing/mitosis-accounting/run.py
```

The runner builds both snapshots in a temporary directory, runs identical
cases, and checks the expected outcome of each. It exits nonzero if any result
differs from its expectation. `CC` can select another C compiler. Temporary
executables are removed automatically. `results.json` records the observed
results; `provenance.json` records source revisions, hashes, and compiler.

The unfixed snapshot fails all fourteen regressions. The fixed snapshot passes
all seventeen cases. All three normal-path controls pass on both snapshots.

| Case | Invariant checked |
| --- | --- |
| `remote-context` | CPU 0 dispatching CPU 1 charges CPU 1's cell counter, even when their cells differ. |
| `remote-clock` | A running timestamp of 1000 ns and remote dispatch at global 1500 ns charge 500 ns despite the executing CPU's local clock reading 500 ns. |
| `remote-subcell` | Remote dispatch charges the target CPU's subcell slot, preserving CPU-based borrowed/lent attribution. |
| `queued-clock` | A 100 ns wait survives migration between CPUs whose local clocks are skewed. |
| `sleep-clock` | A 100 ns sleep survives a wakeup on a CPU with a different local clock. |
| `error-running-cell` | An invalid task cell prevents slice refill after the error. |
| `error-running-pack` | An invalid subcell prevents slice refill after the error. |
| `error-running-map` | A missing runtime accounting slot prevents slice refill. |
| `error-stopping-map` | Failed runtime accounting leaves the next runnable timestamp untouched. |
| `error-quiescent-pack` | Invalid queued-accounting placement leaves later quiescent state untouched. |
| `error-quiescent-map` | A missing queued-accounting slot leaves later quiescent state untouched. |
| `error-running-queued` | Failed queued accounting prevents replacement of slice-start timestamps. |
| `runtime-excludes-nontask` | With different wall and task clock origins, charge only 350 ns of task time during a 500 ns wall interval containing 150 ns of non-task time. |
| `runtime-migration` | Reset the runtime baseline on a new CPU whose task clock is behind the old CPU's; retain 200 ns and 50 ns from the two runs. |
| `wall-demand-window` | Close demand windows on elapsed wall time even when the task clock has a different origin and rate. |
| `no-wait` | A task with no open wait succeeds without looking up an accounting slot. |
| `shared-accounting` | Running, tick, slice extension, and stopping charge a 200 ns run exactly once, retaining normal vtime charging. |

## Snapshots and regeneration

`unfixed.c` and `fixed.c` are generated, self-contained translation units.
The scheduler functions are extracted verbatim from `mitosis.bpf.c`; their
algorithm is not reimplemented in the test. The surrounding harness models the
specific kernel inputs needed for these cases. Both snapshots contain the same
mock environment and test driver.

The unfixed source is the PR rebased onto main with the upstream tick integration
but before the review fixes. The fixed source includes the review fixes.
The exact revisions are in `provenance.json`; those local PR revisions do not
need to be published or fetched to run the included snapshots.

To generate and inspect another snapshot:

```sh
python3 tools/testing/mitosis-accounting/generate.py \
  /path/to/mitosis.bpf.c /tmp/mitosis-accounting-snapshot
```

This writes `accounting-test.c`, its executable, and a `results.json`. The
generator reports each observed result without treating an unfixed regression
as a generator failure. `run.py` provides the expected-outcome assertions for
the two checked-in snapshots.

## Limits

These are deterministic host tests of the extracted callback bodies. They do
not load BPF, run the kernel verifier, enable core scheduling, test concurrency,
or measure clock-read overhead. Unrelated DSQ and LLC behavior is stubbed out.
The injected invalid indexes and missing map slots test error handling; they do
not assert that those conditions arise during normal scheduler operation.

The CPU-context premise was checked separately against Linux's core-scheduling
sibling-runqueue dispatch paths and `scx_bpf_now()`'s use of `this_rq()`.
Runtime uses the target CPU's `scx_clock_task()` / `rq->clock_task` so
accounted IRQ and steal time are excluded. The running callback resets its
baseline after migration. Queued and sleeping intervals, and the elapsed
window used for demand estimation, use `bpf_ktime_get_ns()` across CPUs.
The harness supplies separate wall and per-CPU task clocks to verify that
these timestamp domains are not mixed.

The extracted scheduler bodies retain Meta's copyright notice and are provided
under GPL-2.0-only, as is this harness. See the repository's `LICENSE`.
