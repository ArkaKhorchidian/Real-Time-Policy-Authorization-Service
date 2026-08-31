#!/usr/bin/env python3
"""Assert the benchmark harness produced usable output.

Run in CI after a short sweep. It does NOT check the numbers -- a shared CI
runner cannot produce a latency measurement worth checking -- only that the
harness ran end to end and recorded runs that actually exchanged traffic.
"""

import csv
import os
import sys


def main():
    results = sys.argv[1] if len(sys.argv) > 1 else "bench/results"

    for name in ("summary.csv", "environment.txt", "latency_vs_throughput.svg"):
        path = os.path.join(results, name)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            sys.exit(f"FAIL: {path} is missing or empty")

    with open(os.path.join(results, "summary.csv"), newline="") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        sys.exit("FAIL: summary.csv recorded no runs")

    for r in rows:
        tag = r.get("tag", "?")
        if float(r["sent"]) <= 0:
            sys.exit(f"FAIL: run {tag} sent nothing")
        if float(r["received"]) <= 0:
            sys.exit(f"FAIL: run {tag} received no replies — the server was not answering")
        # Every run must have produced at least one of each verdict; a run where
        # everything was denied usually means the roster failed to load.
        if float(r["allow"]) <= 0:
            sys.exit(f"FAIL: run {tag} produced no ALLOW decisions")

    svg = open(os.path.join(results, "latency_vs_throughput.svg")).read()
    if "<path" not in svg:
        sys.exit("FAIL: the latency figure has no data series")

    print(f"ok: {len(rows)} run(s) recorded, figures rendered")


if __name__ == "__main__":
    main()
