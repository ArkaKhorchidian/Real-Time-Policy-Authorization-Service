#!/usr/bin/env bash
#
# Reproduce every figure in the README with one command.
#
#   ./bench/run.sh                 # full sweep, ~12 minutes
#   ./bench/run.sh --quick         # short runs, ~3 minutes, for a smoke check
#   ./bench/run.sh --only latency  # one section
#
# Everything it produces lands in bench/results/ and is committed: the raw
# summary CSV, the per-run percentile distributions, and the SVGs. The
# environment the numbers came from is captured in bench/results/environment.txt
# on every run, because a latency figure without the machine it ran on is not a
# result -- it is an anecdote.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_DIR="${BUILD_DIR:-build}"
RESULTS="${RESULTS:-bench/results}"
PORT="${PORT:-19500}"
ADMIN_PORT="${ADMIN_PORT:-19501}"
HTTP_PORT="${HTTP_PORT:-19502}"
SUBSCRIBERS="${SUBSCRIBERS:-config/subscribers.csv}"
RULES="${RULES:-config/rules.yaml}"

QUICK=0
ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) QUICK=1; shift ;;
    --only) ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

if [[ $QUICK -eq 1 ]]; then
  DURATION=4; WARMUP=1; SWEEP_QPS="10000 50000 100000 200000"
else
  DURATION=15; WARMUP=3; SWEEP_QPS="10000 25000 50000 100000 150000 200000 300000 400000 500000"
fi

# The load every sweep other than the throughput curve runs at.
#
# It has to be a rate the baseline configuration sustains with no loss.
# Comparing configurations while all of them are past the knee measures the
# depth of a queue, not the thing being varied -- an early version of this
# script swept batch sizes at 200k QPS on a host whose single worker saturates
# near 150k, and every row came back at 45% loss and 100 ms of queueing.
SUSTAINABLE_QPS="${SUSTAINABLE_QPS:-100000}"

# Coordinated omission is invisible on a server with headroom: it only bites
# when the server is sometimes slow, which is exactly when the measurement
# matters. So that comparison deliberately runs just past the knee.
OMISSION_QPS="${OMISSION_QPS:-150000}"

# Idle gap before each measured run. Back-to-back runs on a laptop-class
# machine are not independent samples: sustained 100%-busy threads get hot, and
# on Apple Silicon they also become candidates for demotion to efficiency
# cores, so run N is systematically slower than run N-1. A few seconds of idle
# between runs removes most of that; the repeatability section below is what
# says whether it removed enough.
COOLDOWN="${COOLDOWN:-6}"

# How many times to repeat the headline configuration.
REPEATS="${REPEATS:-5}"
if [[ $QUICK -eq 1 ]]; then REPEATS=2; COOLDOWN=2; fi

# Core placement. Workers take the low cores, the generator takes the high ones,
# so the two never share a core -- sharing one produces a latency figure that is
# mostly scheduler.
NCORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu)"
SERVER_CORE0=0
GEN_CORE0=$(( NCORES / 2 ))
GEN_THREADS=$(( NCORES / 4 )); [[ $GEN_THREADS -lt 1 ]] && GEN_THREADS=1

# Whether the kernel will load-balance across per-worker sockets. Without it,
# workers share one socket, which is a throughput ceiling rather than a property
# of the server -- so the sweep that varies worker count says so.
if "$BUILD_DIR/bin/policyd" --version 2>/dev/null | grep -q "SO_REUSEPORT load balancing: *yes"; then
  PER_WORKER_SOCKETS=1
else
  PER_WORKER_SOCKETS=0
fi

SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

section() { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
note()    { printf '  %s\n' "$*"; }
want()    { [[ -z "$ONLY" || "$ONLY" == "$1" ]]; }

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
section "Build"
cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$BUILD_DIR" -j "$NCORES" >/dev/null
note "built $BUILD_DIR"

POLICYD="$BUILD_DIR/bin/policyd"
LOADGEN="$BUILD_DIR/bin/policy-loadgen"
GENSUBS="$BUILD_DIR/bin/policy-gen-subscribers"

mkdir -p "$RESULTS"

if [[ ! -f "$SUBSCRIBERS" ]]; then
  note "generating $SUBSCRIBERS"
  "$GENSUBS" --count 100000 --rules "$RULES" --out "$SUBSCRIBERS"
fi

# ---------------------------------------------------------------------------
# Environment disclosure
# ---------------------------------------------------------------------------
section "Environment"
ENV_FILE="$RESULTS/environment.txt"
{
  echo "Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Host OS:  $(uname -srm)"
  echo
  echo "--- CPU ---"
  if [[ -r /proc/cpuinfo ]]; then
    grep -m1 'model name' /proc/cpuinfo | sed 's/^[[:space:]]*//'
    echo "cores online: $NCORES"
    echo "governor:     $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'unknown')"
    echo "turbo:        $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null | sed 's/^0$/enabled/;s/^1$/disabled/' || echo 'unknown')"
    echo "isolcpus:     $(cat /sys/devices/system/cpu/isolated 2>/dev/null || echo 'none')"
    echo "SMT:          $(cat /sys/devices/system/cpu/smt/active 2>/dev/null || echo 'unknown')"
    echo "huge pages:   $(grep -c . /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null >/dev/null && cat /sys/kernel/mm/transparent_hugepage/enabled || echo 'unknown')"
  else
    sysctl -n machdep.cpu.brand_string 2>/dev/null || true
    echo "cores online: $NCORES"
    echo "governor:     not applicable (macOS does not expose one)"
    echo "core pinning: unavailable (see below)"
  fi
  echo
  echo "--- Kernel / network ---"
  if [[ -r /proc/version ]]; then
    cat /proc/version
    echo "net.core.rmem_max: $(sysctl -n net.core.rmem_max 2>/dev/null || echo unknown)"
    echo "net.core.wmem_max: $(sysctl -n net.core.wmem_max 2>/dev/null || echo unknown)"
    echo "netdev_max_backlog: $(sysctl -n net.core.netdev_max_backlog 2>/dev/null || echo unknown)"
  else
    echo "kern.ipc.maxsockbuf: $(sysctl -n kern.ipc.maxsockbuf 2>/dev/null || echo unknown)"
  fi
  echo "transport: UDP over loopback (server and generator on one host)"
  echo
  echo "--- Build ---"
  "$POLICYD" --version
  echo
  echo "--- Placement ---"
  echo "server workers start at core $SERVER_CORE0"
  echo "generator threads: $GEN_THREADS starting at core $GEN_CORE0"
} > "$ENV_FILE"
cat "$ENV_FILE"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
start_server() { # workers batch busy_poll backend
  local workers="$1" batch="$2" poll="$3" backend="${4:-udp}"
  cleanup
  "$POLICYD" --workers "$workers" --batch "$batch" --busy-poll-us "$poll" \
             --backend "$backend" --port "$PORT" --admin-port "$ADMIN_PORT" \
             --http-port "$HTTP_PORT" \
             --first-core "$SERVER_CORE0" --rules "$RULES" --subscribers "$SUBSCRIBERS" \
             --no-watch --log-level warn > "$RESULTS/server.log" 2>&1 &
  SERVER_PID=$!
  for _ in $(seq 1 50); do
    if curl -sf "http://127.0.0.1:$ADMIN_PORT/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  echo "server did not become healthy; see $RESULTS/server.log" >&2
  tail -20 "$RESULTS/server.log" >&2
  return 1
}

# The generator's view of a run is only half of it. The server's own counters
# say whether it dropped anything on the send side and what the compute path
# cost, which is how a client-side latency number gets attributed to queueing
# rather than to the decision itself.
capture_server_stats() { # tag
  local tag="$1"
  local json
  json="$(curl -sf "http://127.0.0.1:$ADMIN_PORT/stats" 2>/dev/null || true)"
  [[ -z "$json" ]] && return 0
  local out="$RESULTS/server_stats.csv"
  [[ -f "$out" ]] || echo "tag,requests,replies_sent,short_datagrams,bad_magic,send_failures,mean_batch,service_p50_ns,service_p99_ns,service_p999_ns,service_max_ns,policy_version" > "$out"
  python3 -c '
import json, sys
tag = sys.argv[1]
d = json.loads(sys.argv[2])
s = d["service_ns"]
print(",".join(str(x) for x in [
    tag, d["requests"], d["replies_sent"], d["short_datagrams"], d["bad_magic"],
    d["send_failures"], round(d["mean_batch"], 2), s["p50"], s["p99"], s["p99_9"],
    s["max"], d["policy_version"]]))' "$tag" "$json" >> "$out"
}

run_load() { # tag qps [extra args...]
  local tag="$1" qps="$2"; shift 2
  sleep "$COOLDOWN"
  "$LOADGEN" --server "127.0.0.1:$PORT" --qps "$qps" --duration "$DURATION" \
             --warmup "$WARMUP" --threads "$GEN_THREADS" --first-core "$GEN_CORE0" \
             --rules "$RULES" --subscribers "$SUBSCRIBERS" \
             --summary-csv "$RESULTS/summary.csv" --tag "$tag" "$@" || true
  capture_server_stats "$tag"
}

# ---------------------------------------------------------------------------
# 1. Latency versus offered load
# ---------------------------------------------------------------------------
if want latency; then
  section "Latency versus offered load (1 worker)"
  start_server 1 32 50 udp
  for qps in $SWEEP_QPS; do
    note "offered $qps QPS"
    run_load "sweep-${qps}" "$qps" --out-prefix "$RESULTS/sweep_${qps}" 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  done
fi

# ---------------------------------------------------------------------------
# 2. Worker scaling
# ---------------------------------------------------------------------------
if want scaling; then
  section "Worker scaling at ${SUSTAINABLE_QPS} QPS offered"
  if [[ $PER_WORKER_SOCKETS -eq 0 ]]; then
    note "NOTE: this platform has no SO_REUSEPORT load balancing, so every worker"
    note "      shares one socket. The rows below measure that shared socket, not"
    note "      how the server scales. Run this section on Linux for a real answer."
  fi
  for workers in 1 2 4; do
    note "$workers worker(s)"
    start_server "$workers" 32 50 udp
    run_load "scale-${workers}w" "$SUSTAINABLE_QPS" 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  done
fi

# ---------------------------------------------------------------------------
# 3. Receive batch cap
# ---------------------------------------------------------------------------
if want batch; then
  section "Receive batch cap sweep at ${SUSTAINABLE_QPS} QPS offered"
  # One worker, so the sweep isolates the batch cap rather than mixing it with
  # whatever multiple workers do on this platform's socket.
  for batch in 1 8 32 128; do
    note "batch cap $batch"
    start_server 1 "$batch" 50 udp
    run_load "batch-${batch}" "$SUSTAINABLE_QPS" 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  done
fi

# ---------------------------------------------------------------------------
# 4. Busy-poll budget
# ---------------------------------------------------------------------------
if want poll; then
  section "Busy-poll budget sweep at 20k QPS offered"
  note "deliberately a low rate: the wake-up cost only shows up when the"
  note "inter-arrival gap is longer than the poll budget."
  for poll in 0 10 50 200; do
    note "busy-poll ${poll} us"
    start_server 1 32 "$poll" udp
    run_load "poll-${poll}" 20000 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  done
fi

# ---------------------------------------------------------------------------
# 5. Hot reload under load
# ---------------------------------------------------------------------------
if want reload; then
  section "Hot reload under steady ${SUSTAINABLE_QPS} QPS"
  # One worker: the question is whether a reload perturbs the latency timeline,
  # and a configuration that drops replies for unrelated reasons would bury the
  # answer under its own noise.
  start_server 1 32 50 udp
  ( for _ in $(seq 1 $(( (DURATION + WARMUP) / 5 + 1 )) ); do
      sleep 5
      curl -sf -X POST "http://127.0.0.1:$ADMIN_PORT/rules/reload" >/dev/null 2>&1 || true
    done ) &
  RELOAD_PID=$!
  run_load "reload-steady" "$SUSTAINABLE_QPS" --timeline --out-prefix "$RESULTS/hot_reload" 2>&1 \
    | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  wait $RELOAD_PID 2>/dev/null || true
  note "reload counters:"
  curl -sf "http://127.0.0.1:$ADMIN_PORT/stats" 2>/dev/null \
    | tr ',' '\n' | grep -E 'reload|policy_version' | sed 's/^/    /' || true
fi

# ---------------------------------------------------------------------------
# 6. Coordinated omission: open loop versus closed loop
# ---------------------------------------------------------------------------
if want omission; then
  section "Coordinated omission demonstration at ${OMISSION_QPS} QPS offered"
  start_server 1 32 50 udp
  note "open loop (fixed schedule) -- the honest measurement"
  run_load "omission-open" "$OMISSION_QPS" --out-prefix "$RESULTS/omission_open" 2>&1 \
    | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  note "closed loop (send, wait, send) -- the same server, a client that hides the tail"
  run_load "omission-closed" "$OMISSION_QPS" --closed-loop --out-prefix "$RESULTS/omission_closed" 2>&1 \
    | sed -n '/latency/,/mean/p' | sed 's/^/    /'
fi

# ---------------------------------------------------------------------------
# 7. Ingest backends
# ---------------------------------------------------------------------------
if want backend; then
  section "Ingest backend comparison at ${SUSTAINABLE_QPS} QPS offered"
  for backend in udp io_uring; do
    if [[ "$backend" == "io_uring" ]] && ! "$POLICYD" --version | grep -q "io_uring backend: *yes"; then
      note "io_uring backend not built into this binary; skipping"
      continue
    fi
    note "backend $backend"
    start_server 1 32 50 "$backend"
    run_load "backend-${backend}" "$SUSTAINABLE_QPS" 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  done
fi

# ---------------------------------------------------------------------------
# 8. Protocol overhead
# ---------------------------------------------------------------------------
if want protocol; then
  section "Protocol overhead at ${SUSTAINABLE_QPS} QPS offered"
  note "Same server, same decision path, same rule table, same subscriber store."
  note "The only difference is what goes over the wire, so the gap between these"
  note "two rows is the cost of the protocol and nothing else."
  start_server 1 32 50 udp
  note "binary over UDP, 64 B each way"
  run_load "protocol-udp" "$SUSTAINABLE_QPS" --out-prefix "$RESULTS/protocol_udp" 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  note "HTTP/1.1 GET + JSON, keep-alive"
  "$LOADGEN" --server "127.0.0.1:$HTTP_PORT" --protocol http --connections 64 \
             --qps "$SUSTAINABLE_QPS" --duration "$DURATION" --warmup "$WARMUP" \
             --threads "$GEN_THREADS" --first-core "$GEN_CORE0" \
             --rules "$RULES" --subscribers "$SUBSCRIBERS" \
             --summary-csv "$RESULTS/summary.csv" --tag "protocol-http" \
             --out-prefix "$RESULTS/protocol_http" 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  capture_server_stats "protocol-http"
fi

# ---------------------------------------------------------------------------
# 9. Repeatability
# ---------------------------------------------------------------------------
if want repeat; then
  section "Repeatability: ${REPEATS} runs of the headline configuration"
  note "One run is not a result. This section is what says how much of the"
  note "headline number is the server and how much is the machine it ran on."
  start_server 1 32 50 udp
  for i in $(seq 1 "$REPEATS"); do
    note "repeat $i of $REPEATS"
    run_load "repeat-${i}" "$SUSTAINABLE_QPS" 2>&1 | sed -n '/latency/,/mean/p' | sed 's/^/    /'
  done
fi

cleanup
SERVER_PID=""

# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------
section "Plots and README"
python3 bench/plot.py "$RESULTS"

# Regenerate the README's results tables from the CSVs that were just written.
# No number in the README is ever typed by hand: a README quoting a p99 somebody
# transcribed six weeks ago is exactly the failure this project is about.
python3 bench/update_readme.py README.md "$RESULTS"

section "Done"
note "summary rows : $RESULTS/summary.csv"
note "environment  : $ENV_FILE"
note "figures      : $RESULTS/*.svg"
