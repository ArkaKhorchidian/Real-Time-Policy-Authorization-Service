#!/usr/bin/env python3
"""Render the benchmark CSVs to SVG.

Deliberately dependency-free. The alternative is asking anyone who wants to
reproduce a figure to install matplotlib, and the plots here are simple enough
-- log-y line charts and one timeline -- that hand-written SVG is less code
than the plumbing to configure a plotting library would be.

Every figure carries a CSS block with a prefers-color-scheme rule, so the
committed SVGs stay readable in both GitHub themes instead of being black
lines on a black background for half the people who open the README.

Usage:  python3 bench/plot.py [results_dir]
"""

import csv
import math
import os
import sys

W, H = 900, 520
PAD_L, PAD_R, PAD_T, PAD_B = 78, 190, 46, 62

# Colour-blind-safe qualitative palette (Okabe-Ito), which matters because the
# latency chart puts five series on one axis.
PALETTE = ["#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#56B4E9", "#8C6D31"]

STYLE = """
  .bg { fill: var(--bg); }
  .grid { stroke: var(--grid); stroke-width: 1; }
  .axis { stroke: var(--axis); stroke-width: 1.5; }
  .tick { fill: var(--muted); font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; }
  .label { fill: var(--fg); font: 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  .title { fill: var(--fg); font: 600 15px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  .sub { fill: var(--muted); font: 11px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  .legend { fill: var(--fg); font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }
  .series { fill: none; stroke-width: 2.2; stroke-linejoin: round; stroke-linecap: round; }
  .target { stroke: var(--target); stroke-width: 1.4; stroke-dasharray: 5 4; fill: none; }
  .targetlabel { fill: var(--target); font: 11px -apple-system, BlinkMacSystemFont, sans-serif; }
"""

VARS = """
  :root { --bg:#ffffff; --fg:#1a1a1a; --muted:#6b7280; --grid:#e5e7eb; --axis:#9ca3af; --target:#b91c1c; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0d1117; --fg:#e6edf3; --muted:#8b949e; --grid:#21262d; --axis:#484f58; --target:#f85149; }
  }
"""


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


class Chart:
    """A log-y (optionally log-x) line chart."""

    def __init__(self, title, subtitle, x_label, y_label, log_x=False, log_y=True):
        self.title, self.subtitle = title, subtitle
        self.x_label, self.y_label = x_label, y_label
        self.log_x, self.log_y = log_x, log_y
        self.series = []   # (name, [(x, y)], colour)
        self.hlines = []   # (y, label)

    def add(self, name, points, colour=None):
        points = [(x, y) for x, y in points if y is not None and (not self.log_y or y > 0)]
        if not points:
            return
        if colour is None:
            colour = PALETTE[len(self.series) % len(PALETTE)]
        self.series.append((name, sorted(points), colour))

    def hline(self, y, label):
        self.hlines.append((y, label))

    # -- scales -------------------------------------------------------------
    def _bounds(self):
        xs = [p[0] for _, pts, _ in self.series for p in pts]
        ys = [p[1] for _, pts, _ in self.series for p in pts]
        ys += [y for y, _ in self.hlines]
        if not xs or not ys:
            return 0, 1, 1, 10
        x0, x1 = min(xs), max(xs)
        y0, y1 = min(ys), max(ys)
        if self.log_y:
            y0 = 10 ** math.floor(math.log10(max(y0, 1e-9)))
            y1 = 10 ** math.ceil(math.log10(max(y1, y0 * 1.0001)))
        else:
            span = max(y1 - y0, 1e-9)
            y0, y1 = max(0, y0 - span * 0.1), y1 + span * 0.1
        if self.log_x:
            x0 = 10 ** math.floor(math.log10(max(x0, 1e-9)))
            x1 = 10 ** math.ceil(math.log10(max(x1, x0 * 1.0001)))
        elif x1 == x0:
            x1 = x0 + 1
        return x0, x1, y0, y1

    def _sx(self, x, x0, x1):
        if self.log_x:
            f = (math.log10(max(x, 1e-9)) - math.log10(x0)) / (math.log10(x1) - math.log10(x0))
        else:
            f = (x - x0) / (x1 - x0)
        return PAD_L + f * (W - PAD_L - PAD_R)

    def _sy(self, y, y0, y1):
        if self.log_y:
            f = (math.log10(max(y, 1e-9)) - math.log10(y0)) / (math.log10(y1) - math.log10(y0))
        else:
            f = (y - y0) / (y1 - y0)
        return H - PAD_B - f * (H - PAD_T - PAD_B)

    # -- ticks --------------------------------------------------------------
    @staticmethod
    def _log_ticks(lo, hi):
        out = []
        e = math.floor(math.log10(lo))
        while 10 ** e <= hi * 1.0001:
            for m in (1, 2, 5):
                v = m * 10 ** e
                if lo * 0.999 <= v <= hi * 1.0001:
                    out.append(v)
            e += 1
        return out

    @staticmethod
    def _linear_ticks(lo, hi, count=6):
        span = hi - lo
        if span <= 0:
            return [lo]
        raw = span / count
        mag = 10 ** math.floor(math.log10(raw))
        step = min((1, 2, 5, 10), key=lambda m: abs(m * mag - raw)) * mag
        out, v = [], math.ceil(lo / step) * step
        while v <= hi * 1.0001:
            out.append(v)
            v += step
        return out

    @staticmethod
    def _fmt(v):
        if v >= 1_000_000 and v % 1000 == 0:
            return f"{v/1_000_000:g}M"
        if v >= 1000 and v % 100 == 0:
            return f"{v/1000:g}k"
        if v >= 10:
            return f"{v:.0f}"
        if v >= 1:
            return f"{v:.1f}"
        return f"{v:g}"

    # -- render -------------------------------------------------------------
    def render(self):
        x0, x1, y0, y1 = self._bounds()
        o = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" '
             f'height="{H}" role="img" aria-label="{esc(self.title)}">',
             f"<style>{VARS}{STYLE}</style>",
             f'<rect class="bg" width="{W}" height="{H}"/>',
             f'<text class="title" x="{PAD_L}" y="22">{esc(self.title)}</text>',
             f'<text class="sub" x="{PAD_L}" y="39">{esc(self.subtitle)}</text>']

        y_ticks = self._log_ticks(y0, y1) if self.log_y else self._linear_ticks(y0, y1)
        for t in y_ticks:
            yy = self._sy(t, y0, y1)
            o.append(f'<line class="grid" x1="{PAD_L}" y1="{yy:.1f}" x2="{W-PAD_R}" y2="{yy:.1f}"/>')
            o.append(f'<text class="tick" x="{PAD_L-8}" y="{yy+4:.1f}" text-anchor="end">'
                     f"{self._fmt(t)}</text>")

        x_ticks = self._log_ticks(x0, x1) if self.log_x else self._linear_ticks(x0, x1)
        for t in x_ticks:
            xx = self._sx(t, x0, x1)
            o.append(f'<line class="grid" x1="{xx:.1f}" y1="{PAD_T}" x2="{xx:.1f}" y2="{H-PAD_B}"/>')
            o.append(f'<text class="tick" x="{xx:.1f}" y="{H-PAD_B+18}" text-anchor="middle">'
                     f"{self._fmt(t)}</text>")

        o.append(f'<line class="axis" x1="{PAD_L}" y1="{PAD_T}" x2="{PAD_L}" y2="{H-PAD_B}"/>')
        o.append(f'<line class="axis" x1="{PAD_L}" y1="{H-PAD_B}" x2="{W-PAD_R}" y2="{H-PAD_B}"/>')
        o.append(f'<text class="label" x="{(PAD_L+W-PAD_R)/2:.0f}" y="{H-14}" '
                 f'text-anchor="middle">{esc(self.x_label)}</text>')
        o.append(f'<text class="label" x="18" y="{(PAD_T+H-PAD_B)/2:.0f}" text-anchor="middle" '
                 f'transform="rotate(-90 18 {(PAD_T+H-PAD_B)/2:.0f})">{esc(self.y_label)}</text>')

        for y, label in self.hlines:
            if not (y0 <= y <= y1):
                continue
            yy = self._sy(y, y0, y1)
            o.append(f'<line class="target" x1="{PAD_L}" y1="{yy:.1f}" x2="{W-PAD_R}" y2="{yy:.1f}"/>')
            o.append(f'<text class="targetlabel" x="{W-PAD_R-6}" y="{yy-5:.1f}" '
                     f'text-anchor="end">{esc(label)}</text>')

        for name, pts, colour in self.series:
            d = " ".join(("M" if i == 0 else "L") +
                         f"{self._sx(x,x0,x1):.1f},{self._sy(y,y0,y1):.1f}"
                         for i, (x, y) in enumerate(pts))
            o.append(f'<path class="series" stroke="{colour}" d="{d}"/>')
            for x, y in pts:
                o.append(f'<circle cx="{self._sx(x,x0,x1):.1f}" cy="{self._sy(y,y0,y1):.1f}" '
                         f'r="3" fill="{colour}"/>')

        ly = PAD_T + 8
        for name, _, colour in self.series:
            o.append(f'<rect x="{W-PAD_R+14}" y="{ly-9}" width="14" height="3" rx="1.5" fill="{colour}"/>')
            o.append(f'<text class="legend" x="{W-PAD_R+34}" y="{ly-3}">{esc(name)}</text>')
            ly += 22

        o.append("</svg>")
        return "\n".join(o)


def read_csv(path):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return [r for r in csv.DictReader(l for l in f if not l.startswith("#"))]


def num(row, key, default=None):
    try:
        return float(row[key])
    except (KeyError, TypeError, ValueError):
        return default


def write(path, svg):
    with open(path, "w") as f:
        f.write(svg)
    print(f"  wrote {path}")


def plot_latency_curve(d, rows):
    rows = [r for r in rows if r.get("tag", "").startswith("sweep-")]
    if not rows:
        return
    workers = sorted({r["threads"] for r in rows})
    c = Chart("Latency versus offered load",
              "open-loop generator, latency measured from the scheduled send time; "
              "log-y. Lower is better.",
              "offered load (requests/second)", "latency (microseconds)", log_x=True)
    for pct, key in (("p50", "p50_us"), ("p99", "p99_us"),
                     ("p99.9", "p999_us"), ("p99.99", "p9999_us")):
        c.add(pct, [(num(r, "offered_qps"), num(r, key)) for r in rows])
    c.hline(500, "p99 target 500 us")
    c.hline(50, "p50 target 50 us")
    write(os.path.join(d, "latency_vs_throughput.svg"), c.render())
    del workers


def plot_scaling(d, rows):
    rows = [r for r in rows if r.get("tag", "").startswith("scale-")]
    if not rows:
        return
    c = Chart("Worker scaling at a fixed offered load",
              "same offered load, 1/2/4 worker threads. Flat is good: it means "
              "workers are not contending.",
              "worker threads", "latency (microseconds)")
    for pct, key in (("p50", "p50_us"), ("p99", "p99_us"), ("p99.9", "p999_us")):
        c.add(pct, [(float(r["tag"].split("-")[1].rstrip("w")), num(r, key)) for r in rows])
    write(os.path.join(d, "scaling.svg"), c.render())


def plot_batch(d, rows):
    rows = [r for r in rows if r.get("tag", "").startswith("batch-")]
    if not rows:
        return
    c = Chart("Receive batch cap versus latency",
              "a larger batch amortizes the syscall over more requests, but the "
              "first request in a batch waits for the whole batch.",
              "batch cap (datagrams per receive)", "latency (microseconds)", log_x=True)
    for pct, key in (("p50", "p50_us"), ("p99", "p99_us"), ("p99.9", "p999_us")):
        c.add(pct, [(float(r["tag"].split("-")[1]), num(r, key)) for r in rows])
    write(os.path.join(d, "batch_sweep.svg"), c.render())


def plot_busy_poll(d, rows):
    rows = [r for r in rows if r.get("tag", "").startswith("poll-")]
    if not rows:
        return
    c = Chart("Busy-poll budget versus latency",
              "spinning before parking removes the wake-up path from the latency "
              "of the next request, at the cost of a core.",
              "busy-poll budget (microseconds, 0 = park immediately)",
              "latency (microseconds)")
    for pct, key in (("p50", "p50_us"), ("p99", "p99_us"), ("p99.9", "p999_us")):
        c.add(pct, [(float(r["tag"].split("-")[1]), num(r, key)) for r in rows])
    write(os.path.join(d, "busy_poll_sweep.svg"), c.render())


def plot_reload_timeline(d):
    rows = read_csv(os.path.join(d, "hot_reload.timeline.csv"))
    if not rows:
        return
    c = Chart("Hot reload under steady load",
              "rule set swapped every 5 s at a constant offered load. A reload that "
              "stalled workers would show as a spike.",
              "elapsed time (seconds)", "p99 latency (microseconds)")
    c.add("p99 per second", [(num(r, "second"), num(r, "p99_us")) for r in rows])
    write(os.path.join(d, "hot_reload_timeline.svg"), c.render())


def plot_open_vs_closed(d):
    """The figure that shows what coordinated omission actually costs."""
    series = []
    for tag, label in (("open", "open loop (fixed schedule)"),
                       ("closed", "closed loop (send, wait, send)")):
        rows = read_csv(os.path.join(d, f"omission_{tag}.hdr.csv"))
        pts = []
        for r in rows:
            p = num(r, "Percentile")
            v = num(r, "Value")
            if p is None or v is None or p >= 1.0:
                continue
            pts.append((1.0 / (1.0 - p), v / 1000.0))
        if pts:
            series.append((label, pts))
    if not series:
        return
    c = Chart("Coordinated omission: the same server, two clients",
              "identical offered load. The closed-loop client stops sending while the "
              "server is slow, so its tail is missing the requests that were slowest.",
              "1 / (1 - percentile)   —   10 = p90, 100 = p99, 1000 = p99.9",
              "latency (microseconds)", log_x=True)
    for label, pts in series:
        c.add(label, pts)
    write(os.path.join(d, "coordinated_omission.svg"), c.render())


def plot_backends(d, rows):
    rows = [r for r in rows if r.get("tag", "").startswith("backend-")]
    if len(rows) < 2:
        return
    c = Chart("Ingest backend comparison",
              "same offered load and batch cap through each ingest path.",
              "percentile", "latency (microseconds)", log_x=True)
    for r in rows:
        name = r["tag"].split("-", 1)[1]
        c.add(name, [(2, num(r, "p50_us")), (10, num(r, "p90_us")), (100, num(r, "p99_us")),
                     (1000, num(r, "p999_us")), (10000, num(r, "p9999_us"))])
    write(os.path.join(d, "backend_comparison.svg"), c.render())


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "results")
    summary = read_csv(os.path.join(d, "summary.csv"))
    if not summary:
        print(f"no summary.csv in {d}; run bench/run.sh first", file=sys.stderr)
    print(f"plotting {len(summary)} run(s) from {d}")
    plot_latency_curve(d, summary)
    plot_scaling(d, summary)
    plot_batch(d, summary)
    plot_busy_poll(d, summary)
    plot_backends(d, summary)
    plot_reload_timeline(d)
    plot_open_vs_closed(d)


if __name__ == "__main__":
    main()
