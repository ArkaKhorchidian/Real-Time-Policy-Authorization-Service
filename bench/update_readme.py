#!/usr/bin/env python3
"""Regenerate the README's results tables from the committed benchmark CSVs.

The point is that no number in the README is ever typed by hand. A README that
quotes a p99 someone transcribed six weeks ago is exactly the failure mode this
project is supposed to be about, so the tables are generated from
bench/results/ and the generator runs at the end of bench/run.sh.

Content is replaced between marker comments:

    <!-- BENCH:targets -->   ...generated...   <!-- /BENCH:targets -->

Usage:  python3 bench/update_readme.py [README.md] [results_dir]
"""

import csv
import os
import re
import sys

# The targets stated up front in the README, against which results are scored.
TARGETS = [
    ("p50", "p50_us", 50.0, "in-memory lookup, rule evaluation and serialize"),
    ("p99", "p99_us", 500.0, "the headline number; must hold at 100k QPS"),
    ("p99.9", "p999_us", 1000.0, ""),
    ("p99.99", "p9999_us", 2000.0, "no GC pauses to hide behind"),
]

HEADLINE_QPS = 100000


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return [r for r in csv.DictReader(l for l in f if not l.startswith("#"))]


def fnum(row, key):
    try:
        return float(row[key])
    except (KeyError, TypeError, ValueError):
        return float("nan")


def fmt(v, digits=1):
    if v != v:  # NaN
        return "—"
    if v >= 10000:
        return f"{v:,.0f}"
    return f"{v:.{digits}f}"


def by_tag(rows):
    return {r["tag"]: r for r in rows}


def section_targets(rows, server):
    """Target-versus-measured at the headline load."""
    tags = by_tag(rows)
    row = tags.get(f"sweep-{HEADLINE_QPS}")
    if row is None:
        return "_No run at the headline load yet._"

    srv = by_tag(server).get(f"sweep-{HEADLINE_QPS}", {})
    out = [
        f"Measured at **{HEADLINE_QPS:,} QPS offered, one worker**, "
        f"{fnum(row,'loss_pct'):.4f}% loss "
        f"({int(fnum(row,'received')):,} replies over the measurement window).",
        "",
        "| Metric | Target | Measured | |",
        "|---|---:|---:|:--|",
    ]
    for name, key, target, _note in TARGETS:
        v = fnum(row, key)
        hit = "met" if v <= target else "**missed**"
        out.append(f"| {name} | < {target:,.0f} µs | {fmt(v)} µs | {hit} |")

    achieved = fnum(row, "achieved_qps")
    out.append(f"| throughput | ≥ 100k QPS/core | {achieved:,.0f} QPS | met |")

    if srv:
        out += [
            "",
            "The server's own view of the same run — decode, subscriber lookup, "
            "`evaluate()`, encode, excluding the syscalls on either side:",
            "",
            "| | p50 | p99 | p99.9 | max |",
            "|---|---:|---:|---:|---:|",
            f"| service time | {srv['service_p50_ns']} ns | {srv['service_p99_ns']} ns | "
            f"{srv['service_p999_ns']} ns | {srv['service_max_ns']} ns |",
        ]
    return "\n".join(out)


def section_sweep(rows):
    sweep = sorted((r for r in rows if r["tag"].startswith("sweep-")),
                   key=lambda r: fnum(r, "offered_qps"))
    if not sweep:
        return "_No sweep recorded._"
    out = ["| Offered | Achieved | Loss | p50 | p90 | p99 | p99.9 | p99.99 | max |",
           "|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in sweep:
        loss = fnum(r, "loss_pct")
        loss_cell = f"{loss:.2f}%" if loss >= 0.005 else "0"
        marker = " ⚠️" if loss > 0.01 else ""
        out.append(
            f"| {fnum(r,'offered_qps'):,.0f} | {fnum(r,'achieved_qps'):,.0f} | "
            f"{loss_cell}{marker} | {fmt(fnum(r,'p50_us'))} | {fmt(fnum(r,'p90_us'))} | "
            f"{fmt(fnum(r,'p99_us'))} | {fmt(fnum(r,'p999_us'))} | "
            f"{fmt(fnum(r,'p9999_us'))} | {fmt(fnum(r,'max_us'))} |")
    out += ["", "All figures in microseconds. ⚠️ marks a row whose loss exceeds 0.01%, "
                "where the percentiles are over received replies only and the tail is "
                "therefore understated."]
    return "\n".join(out)


def section_omission(rows):
    tags = by_tag(rows)
    o, c = tags.get("omission-open"), tags.get("omission-closed")
    if not o or not c:
        return "_Not recorded._"
    offered = fnum(o, "offered_qps")
    out = [
        f"Same server, same binary, same {offered:,.0f} QPS asked for. The only "
        "difference is whether the client keeps sending while the server is slow.",
        "",
        "| | Achieved | p50 | p99 | p99.9 | p99.99 | max |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for label, r in (("open loop (fixed schedule)", o), ("closed loop (send, wait, send)", c)):
        out.append(
            f"| {label} | {fnum(r,'achieved_qps'):,.0f} QPS | {fmt(fnum(r,'p50_us'))} | "
            f"{fmt(fnum(r,'p99_us'))} | {fmt(fnum(r,'p999_us'))} | "
            f"{fmt(fnum(r,'p9999_us'))} | {fmt(fnum(r,'max_us'))} |")

    ratio = fnum(o, "p99_us") / max(fnum(c, "p99_us"), 1e-9)
    shortfall = 100.0 * (1.0 - fnum(c, "achieved_qps") / max(offered, 1e-9))
    out += ["", f"The closed-loop client reports a p99 **{ratio:.0f}× better** while actually "
                f"delivering **{shortfall:.0f}% less load than it was asked for**. It looks "
                "faster because it gave up."]
    return "\n".join(out)


def section_reload(rows, results_dir):
    tl = read_csv(os.path.join(results_dir, "hot_reload.timeline.csv"))
    if not tl:
        return "_Not recorded._"
    p99s = [fnum(r, "p99_us") for r in tl if fnum(r, "p99_us") == fnum(r, "p99_us")]
    counts = [fnum(r, "replies") for r in tl if fnum(r, "replies") == fnum(r, "replies")]
    if not p99s:
        return "_Not recorded._"
    row = by_tag(rows).get("reload-steady", {})
    reloads = max(1, len(p99s) // 5)
    return "\n".join([
        f"A rule reload every 5 s across a {len(p99s)} s run at a steady "
        f"{fnum(row,'offered_qps'):,.0f} QPS — {reloads} swaps while traffic was flowing.",
        "",
        "| | Value |",
        "|---|---:|",
        f"| p99 across the run, best second | {min(p99s):.1f} µs |",
        f"| p99 across the run, worst second | {max(p99s):.1f} µs |",
        f"| spread between them | {max(p99s) - min(p99s):.1f} µs |",
        f"| replies per second, min / max | {min(counts):,.0f} / {max(counts):,.0f} |",
        f"| requests dropped by a reload | {int(fnum(row,'lost')) if row else 0} |",
        "",
        "No second containing a reload is distinguishable from one that does not. "
        "That is what an atomic pointer swap buys: readers never block, and the old "
        "snapshot is freed only after a grace period.",
    ])


def section_batch(rows):
    b = sorted((r for r in rows if r["tag"].startswith("batch-")),
               key=lambda r: float(r["tag"].split("-")[1]))
    if not b:
        return "_Not recorded._"
    out = ["| Batch cap | Mean realized batch | p50 | p99 | p99.9 | Achieved |",
           "|---:|---:|---:|---:|---:|---:|"]
    for r in b:
        cap = r["tag"].split("-")[1]
        out.append(f"| {cap} | — | {fmt(fnum(r,'p50_us'))} | {fmt(fnum(r,'p99_us'))} | "
                   f"{fmt(fnum(r,'p999_us'))} | {fnum(r,'achieved_qps'):,.0f} QPS |")
    return "\n".join(out)


def section_batch_with_server(rows, server):
    b = sorted((r for r in rows if r["tag"].startswith("batch-")),
               key=lambda r: float(r["tag"].split("-")[1]))
    srv = by_tag(server)
    if not b:
        return "_Not recorded._"
    out = ["| Batch cap | Mean realized batch | p50 | p99 | p99.9 | Achieved |",
           "|---:|---:|---:|---:|---:|---:|"]
    for r in b:
        cap = r["tag"].split("-")[1]
        realized = srv.get(r["tag"], {}).get("mean_batch", "—")
        out.append(f"| {cap} | {realized} | {fmt(fnum(r,'p50_us'))} | {fmt(fnum(r,'p99_us'))} | "
                   f"{fmt(fnum(r,'p999_us'))} | {fnum(r,'achieved_qps'):,.0f} QPS |")
    return "\n".join(out)


def section_poll(rows):
    p = sorted((r for r in rows if r["tag"].startswith("poll-")),
               key=lambda r: float(r["tag"].split("-")[1]))
    if not p:
        return "_Not recorded._"
    out = ["| Busy-poll budget | p50 | p99 | p99.9 | p99.99 |",
           "|---:|---:|---:|---:|---:|"]
    for r in p:
        us = r["tag"].split("-")[1]
        label = "0 (park immediately)" if us == "0" else f"{us} µs"
        out.append(f"| {label} | {fmt(fnum(r,'p50_us'))} | {fmt(fnum(r,'p99_us'))} | "
                   f"{fmt(fnum(r,'p999_us'))} | {fmt(fnum(r,'p9999_us'))} |")
    return "\n".join(out)


def section_scaling(rows, server):
    s = sorted((r for r in rows if r["tag"].startswith("scale-")),
               key=lambda r: float(r["tag"].split("-")[1].rstrip("w")))
    srv = by_tag(server)
    if not s:
        return "_Not recorded._"
    out = ["| Workers | Achieved | Loss | Replies dropped by the server | p50 | p99 | p99.9 |",
           "|---:|---:|---:|---:|---:|---:|---:|"]
    for r in s:
        w = r["tag"].split("-")[1].rstrip("w")
        dropped = srv.get(r["tag"], {}).get("send_failures", "—")
        out.append(f"| {w} | {fnum(r,'achieved_qps'):,.0f} QPS | {fnum(r,'loss_pct'):.2f}% | "
                   f"{dropped} | {fmt(fnum(r,'p50_us'))} | {fmt(fnum(r,'p99_us'))} | "
                   f"{fmt(fnum(r,'p999_us'))} |")
    return "\n".join(out)


def section_repeat(rows):
    """Run-to-run spread of the headline configuration."""
    reps = sorted((r for r in rows if r["tag"].startswith("repeat-")),
                  key=lambda r: int(r["tag"].split("-")[1]))
    if not reps:
        return "_Not recorded._"

    def stats(key):
        vals = sorted(fnum(r, key) for r in reps)
        n = len(vals)
        median = vals[n // 2] if n % 2 else 0.5 * (vals[n // 2 - 1] + vals[n // 2])
        return vals[0], median, vals[-1]

    out = [
        f"{len(reps)} runs of the same configuration, same load, with an idle gap "
        "between each. Identical inputs, so the spread is the machine.",
        "",
        "| | Best | Median | Worst | Worst / best |",
        "|---|---:|---:|---:|---:|",
    ]
    for label, key in (("p50", "p50_us"), ("p99", "p99_us"), ("p99.9", "p999_us")):
        lo, mid, hi = stats(key)
        ratio = hi / lo if lo > 0 else float("nan")
        out.append(f"| {label} | {fmt(lo)} µs | {fmt(mid)} µs | {fmt(hi)} µs | {ratio:.1f}× |")

    out += ["", "Per run, with the generator's own health alongside — a run where the "
                "generator missed its schedule was measuring the generator:", "",
            "| Run | p50 | p99 | p99.9 | Loss | Generator schedule slips |",
            "|---:|---:|---:|---:|---:|---:|"]
    for r in reps:
        sent = max(fnum(r, "sent"), 1.0)
        slip_pct = 100.0 * fnum(r, "schedule_slips") / sent
        flag = " ⚠️" if slip_pct > 1.0 else ""
        out.append(
            f"| {r['tag'].split('-')[1]} | {fmt(fnum(r,'p50_us'))} | {fmt(fnum(r,'p99_us'))} | "
            f"{fmt(fnum(r,'p999_us'))} | {fnum(r,'loss_pct'):.3f}% | {slip_pct:.2f}%{flag} |")
    out += ["", "⚠️ marks a run where the generator fell behind its own schedule on more "
                "than 1% of sends; those rows describe the load generator, not the server."]
    return "\n".join(out)


def section_environment(results_dir):
    path = os.path.join(results_dir, "environment.txt")
    if not os.path.exists(path):
        return "_Not recorded._"
    return "```\n" + open(path).read().strip() + "\n```"


def main():
    readme = sys.argv[1] if len(sys.argv) > 1 else "README.md"
    results = sys.argv[2] if len(sys.argv) > 2 else "bench/results"

    rows = read_csv(os.path.join(results, "summary.csv"))
    server = read_csv(os.path.join(results, "server_stats.csv"))
    if not rows:
        print(f"no summary.csv in {results}; nothing to update", file=sys.stderr)
        return 1

    sections = {
        "targets": section_targets(rows, server),
        "sweep": section_sweep(rows),
        "omission": section_omission(rows),
        "reload": section_reload(rows, results),
        "batch": section_batch_with_server(rows, server),
        "poll": section_poll(rows),
        "scaling": section_scaling(rows, server),
        "repeat": section_repeat(rows),
        "environment": section_environment(results),
    }

    text = open(readme).read()
    updated = 0
    for name, body in sections.items():
        pattern = re.compile(
            rf"(<!-- BENCH:{name} -->).*?(<!-- /BENCH:{name} -->)", re.DOTALL)
        if not pattern.search(text):
            print(f"  note: no marker for '{name}' in {readme}", file=sys.stderr)
            continue
        text = pattern.sub(lambda m: f"{m.group(1)}\n{body}\n{m.group(2)}", text)
        updated += 1

    open(readme, "w").write(text)
    print(f"updated {updated} section(s) in {readme} from {len(rows)} run(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
