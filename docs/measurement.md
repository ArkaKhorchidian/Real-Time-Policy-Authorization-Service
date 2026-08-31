# How the numbers were measured

Most latency benchmarks are wrong in the same few ways, and a carrier engineer
reading a p99 will ask about all of them. This document answers those questions
before they are asked.

## 1. Coordinated omission

The problem, in one sentence: **a client that waits for a reply before sending
the next request stops offering load exactly when the server is slow, so the
requests it never sent are precisely the ones that would have been slowest.**

Concretely. A closed-loop client at a nominal 100k QPS sends, waits, sends. The
server stalls for 10 ms. During that stall the client issues *one* request
instead of the thousand the schedule called for. The histogram gets one sample
of 10 ms instead of a thousand samples averaging 5 ms. The reported p99 improves
because the server got slower. That is not a subtle bias; it can be two orders
of magnitude at the tail.

This project's generator issues requests on a **fixed schedule** — one every
10 µs for 100k QPS — regardless of what has come back, and records

```
latency = receive_timestamp − SCHEDULED send time
```

not `receive − actual send`. If the generator is late issuing a request, that
lateness is charged to the measurement, because a real caller would have
experienced it.

`--closed-loop` runs the naive scheme deliberately, against the same server at
the same offered load, so the difference is a number in
`bench/results/coordinated_omission.svg` rather than an assertion.

## 2. The generator measures itself

An open-loop generator that cannot keep to its own schedule produces numbers
about the generator. So it reports, separately from latency:

- **`send_lateness`** — the distribution of `actual send − scheduled send`.
- **`schedule_slips`** — how many sends fell more than one interval behind, and
  the worst one.

If slips exceed 1% of sends, the run prints a warning saying it measured the
generator rather than the server. When reading `summary.csv`, a large
`send_late_p99_us` invalidates the row.

## 3. Loss is reported, never absorbed

Percentiles are computed over replies **actually received**. A run that lost
2% of its datagrams has had its slowest samples silently deleted, and its p99 is
not a p99. So:

- loss is printed as a count and a percentage,
- a run above 0.01% loss is labelled `DEGRADED` and the generator exits
  non-zero, so a sweep script notices without parsing output,
- requests still in flight when the measurement window closes are given the
  full timeout to return, rather than being counted as loss.

That last point mattered: an early version of the harness reported a steady
~1-in-100,000 phantom loss rate. The cause was an unsigned underflow — the
timeout sweep compared against a timestamp cached at the top of the loop, so
requests sent later in the same iteration had a `sent_ns` in the future, the
subtraction wrapped to a colossal age, and they were written off microseconds
after being sent. **A measurement harness needs debugging like anything else**,
and a small unexplained error rate is where its bugs hide.

## 4. Percentiles come from a histogram, not from sorted samples

Sorting ten million samples to find p99.99 costs more than the benchmark and
tempts people to down-sample — which is how tails vanish. `HdrHistogram`
records in constant time (a count-leading-zeros, a shift and an increment, about
2 ns) with a bounded *relative* error: at three significant figures, every
reported value is within 0.1% of the true one whether it is 2 µs or 2 seconds.

Two consequences worth knowing when reading the output:

- Every percentile is reported as the **top of the bucket** the value fell in,
  so `value_at_percentile(100)` is at or slightly above the exact `max()`.
- Values above the tracked range are **clamped and counted**, never dropped.
  `overflow_count()` is non-zero if that happened.

`tests/test_hdr.cpp` validates the implementation against exact percentiles
computed from sorted reference data, for uniform, log-normal-with-outliers and
bimodal distributions.

## 5. What the server measures about itself

The generator's number is end-to-end: two syscalls, two trips through the
network stack, two scheduler decisions, and the decision itself. The server
separately measures **service time** — decode, subscriber lookup, `evaluate()`,
encode — with the cycle counter (`cntvct_el0` on AArch64, `rdtsc` on x86-64),
because two `clock_gettime` calls at ~20 ns each would be a tenth of the thing
being measured and would put the vDSO's own variance into the tail.

The counter's read cost is measured at startup and printed in the banner. It is
**reported, never subtracted**: silently correcting a measurement by an estimate
is how instruments start lying.

The gap between the two numbers is the I/O and scheduling cost, and on this
project it is where essentially all the latency lives. That is the honest
headline: the compute path is effectively free, and the system's latency is a
signalling and scheduling question.

## 6. Placement

`bench/run.sh` puts server workers on the low cores and generator threads on the
high ones. A generator sharing a core with the server produces a latency figure
that is mostly scheduler.

Server and generator run on **one host over loopback** unless
`bench/results/environment.txt` says otherwise. That removes the NIC and the
wire, which flatters the absolute numbers, while adding contention for cores and
memory bandwidth, which does not. It is disclosed rather than corrected for. A
two-machine run over a real NIC is the right next step and would move the floor
up by the wire time.

## 7. Environment disclosure

`bench/results/environment.txt` is regenerated on every run and records the CPU
model, cores online, frequency governor, turbo state, `isolcpus`, SMT, huge
pages, kernel version, socket buffer limits, compiler and build type, and the
core placement used. A latency figure without the machine it ran on is an
anecdote.

## 8. What CI does and does not tell you

CI runs `bench/run.sh --quick` to prove the harness still works end to end, and
uploads the output as an artifact. **Those numbers are not results.** A shared
cloud runner with no core isolation, an unknown neighbour and an unknown
governor cannot produce a tail-latency measurement worth quoting, and the job is
named to say so.

## Reproducing

```
./bench/run.sh              # full sweep
./bench/run.sh --quick      # short runs, for a smoke check
./bench/run.sh --only latency
```

Everything lands in `bench/results/`: the raw summary CSV, per-run percentile
distributions in HdrHistogram CSV form, the server's own counters for the same
runs, and the SVG figures.
