# Architecture

```
                                    ┌──────────────────────────────────────────┐
  load generator ──UDP, 64 B────────▶│  worker 0        (pinned, core 0)        │
  (open loop, separate cores)        │   SO_REUSEPORT socket, kernel-hashed     │
                                     │   recvmmsg batch                         │
                                     │        │                                 │
                                     │        ▼                                 │
                                     │   decode (fixed 64 B, one memcpy)        │
                                     │        ▼                                 │
                                     │   SubscriberStore::find(imsi)            │
                                     │     flat open addressing, 1 cache miss   │
                                     │        ▼                                 │
                                     │   build_features()  ──▶ 64-bit word      │
                                     │        ▼                                 │
                                     │   evaluate()                             │
                                     │     linear scan of 64 B CompiledRules    │
                                     │     read via RCU snapshot (1 acquire)    │
                                     │        ▼                                 │
                                     │   encode + sendmmsg batch                │
                                     ├──────────────────────────────────────────┤
                                     │  worker 1..N-1   (same, share nothing)   │
                                     └──────────────────────────────────────────┘
                                                       ▲
                                     ┌─────────────────┴────────────────────────┐
                                     │  control plane (own thread, off the path)│
                                     │   subscriber CSV loader (startup)        │
                                     │   rules file watcher → compile → RCU swap│
                                     │   coarse clock ticker (100 ms)           │
                                     │   admin HTTP: /metrics /stats /rules     │
                                     │               /rules/reload /explain     │
                                     │               /subscriber/{imsi}         │
                                     └──────────────────────────────────────────┘
```

## What the request path touches

Per request, in order:

1. **One 64-byte memcpy** out of the receive buffer, plus a magic check.
2. **One hash and one cache miss** in the subscriber store. Records live inline
   in the slot array, so the probe load and the record load are the same load.
3. **One 64-bit feature word**, built from the request, the record and the rule
   set's interned thresholds.
4. **A linear scan** of the compiled rule table until the first match. The
   shipped policy is 26 compiled rules — 1,664 bytes — which is resident in L1d
   and prefetched perfectly because the scan is sequential.
5. **One 64-byte memcpy** into the send buffer.

Per *batch* (not per request): one acquire load for the RCU snapshot, one
`recvmmsg`, one `sendmmsg`.

Nothing on that path allocates, locks, throws, or makes a syscall. The
allocation claim is tested rather than asserted — `tests/test_engine.cpp` runs
20,000 evaluations under a counting global allocator and requires the count not
to move.

## Share-nothing between workers

Each worker owns:

- its own socket (Linux: `SO_REUSEPORT`, the kernel hashes flows across the
  group; elsewhere: a shared socket, see below),
- its own receive and send buffers,
- its own cache-line-aligned metrics block, including its own histogram,
- its own RCU reader slot, on its own cache line.

The only memory two workers both touch is read-only: the rule set snapshot and
the subscriber store. There is no shared counter incremented per request — at
100k QPS per core that is a contended cache line, and it would show up directly
in the p99.

## The RCU swap

```
reader:  slot.epoch.store(global_epoch, release)     // enter
         fence(seq_cst)
         rs = current.load(acquire)                  // snapshot
         ... evaluate a batch against rs ...
         slot.epoch.store(QUIESCENT, release)        // leave

writer:  old = current.exchange(new, acq_rel)
         global_epoch.fetch_add(1, release)
         fence(seq_cst)
         wait until every slot is quiescent or at the new epoch
         delete old
```

The reader's two stores go to a line that core already owns exclusively, and the
acquire load is of a line that is read-shared and almost never written. The
`seq_cst` fences pair: without them, store-load reordering would let a writer
miss a reader's epoch *and* that reader miss the new pointer at the same time.

`synchronize()` takes a timeout. A reader cannot legitimately stall inside its
critical section — it is a bounded, allocation-free, branch-only scan — but a
bug must not be able to wedge the control plane, so on timeout the old snapshot
is parked for a later grace period rather than freed or waited on forever.

The snapshot is acquired **once per batch**, not once per request. That
amortizes the epoch store and guarantees every request in a batch is decided
against one policy version, which matters when someone is reading an audit log.

## Why a linear rule scan

A realistic operator policy is 50–200 rules. At 64 bytes each that is 3–13 KB,
which lives in L1d, and the scan is sequential so the hardware prefetcher covers
it perfectly. Matching one rule is two ANDs, a compare and a test — no data
dependency between iterations, so the loop pipelines.

A decision tree or interval index would replace ~100 predictable, pipelined
iterations with ~7 *dependent* loads and unpredictable branches. At this size
that is slower, not faster. It becomes the right structure somewhere in the
thousands of rules, and `bench/results/` is where that crossover would be
measured before anyone changed it.

The linear scan is also why conditions that are not naturally boolean — "usage
above 80%", "between 02:00 and 06:00" — are turned into bits at *compile* time.
The compiler interns the distinct thresholds a file mentions and assigns each a
feature bit, so the per-request cost is one comparison per distinct threshold
rather than one per rule.

## The platform split, stated plainly

| | Linux | macOS / BSD |
|---|---|---|
| Socket per worker | `SO_REUSEPORT`, kernel-hashed | one shared socket — BSD `SO_REUSEPORT` does not load-balance and there is no `SO_REUSEPORT_LB` on macOS |
| Batched I/O | `recvmmsg` / `sendmmsg`, one syscall per batch | a loop of `recvfrom` / `sendto`, N syscalls |
| CPU pinning | `sched_setaffinity`, real | none — affinity tags are advisory on Intel and ignored on Apple Silicon |
| io_uring backend | built when liburing is present | not available |

Both paths work and both measure something real, but **only the Linux numbers
are comparable to a production deployment.** The binary reports which path is
live in its startup banner, on `/stats`, and in `--version`, so a benchmark
result cannot accidentally be attributed to the wrong one.

## Control plane

Runs on its own thread and never touches worker state except through the same
RCU snapshot workers read. An admin request cannot slow a decision down.

It owns the rules-file watcher (mtime polling — 30 lines rather than two
platform-specific implementations, and immune to the editor-rename problem that
makes naive inotify watches stop working after the first save), the coarse clock
that the decision path reads instead of calling `clock_gettime`, and the admin
HTTP server.

A reload that fails to compile leaves the previous rule set live. A reload that
renames or reorders a plan is refused outright: subscriber records store plan
indices, so accepting it would silently move subscribers onto different tariffs.

## Where this sits in a real core network

This is the PCF decision path (5G) or PCRF (4G), plus the AAA-style "is this
subscriber allowed on the network at all" check. In a real core it sits behind
Diameter Gx or HTTP/2 Npcf signalling and in front of a database of record.

The honest framing: **this project shows the compute path can be made
effectively free.** Service time is measured in hundreds of nanoseconds while
end-to-end latency is measured in tens of microseconds — the difference is
syscalls, scheduling and the network stack. Which means that in a real
deployment the system's latency is a signalling and persistence question, not a
policy-evaluation one, and that is where the next round of work belongs.
