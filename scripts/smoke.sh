#!/usr/bin/env bash
#
# End-to-end smoke test: start the server, drive real traffic through it, and
# check both the decisions and the operational surface.
#
# This is the test that would catch a server that builds, passes every unit
# test, and then answers nothing — which no amount of unit testing does.
#
#   ./scripts/smoke.sh [udp|io_uring]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BACKEND="${1:-udp}"
BUILD_DIR="${BUILD_DIR:-build}"
PORT="${PORT:-19600}"
ADMIN_PORT="${ADMIN_PORT:-19601}"
HTTP_PORT="${HTTP_PORT:-19602}"
LOG="$(mktemp -t policyd-smoke.XXXXXX)"

POLICYD="$BUILD_DIR/bin/policyd"
LOADGEN="$BUILD_DIR/bin/policy-loadgen"

SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$LOG"
}
trap cleanup EXIT INT TERM

fail() { echo "SMOKE FAIL: $*" >&2; echo "--- server log ---" >&2; cat "$LOG" >&2; exit 1; }
ok()   { echo "  ok  $*"; }

echo "smoke test: backend=$BACKEND"

"$POLICYD" --workers 2 --backend "$BACKEND" --port "$PORT" --admin-port "$ADMIN_PORT" \
           --http-port "$HTTP_PORT" --no-pin --no-watch --log-level info > "$LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$ADMIN_PORT/healthz" >/dev/null 2>&1 && break
  sleep 0.25
done
curl -sf "http://127.0.0.1:$ADMIN_PORT/healthz" >/dev/null || fail "server never became healthy"
ok "server is healthy"

# --- traffic ---------------------------------------------------------------
# Deliberately a modest rate. This test is about "does the whole thing work",
# not about how fast it is, and a shared CI runner cannot answer the second
# question anyway. A rate high enough to make CI flaky would only teach people
# to ignore the job.
"$LOADGEN" --server "127.0.0.1:$PORT" --qps 10000 --duration 3 --warmup 1 \
           --threads 1 --no-pin --timeout-ms 500 > /tmp/smoke-loadgen.txt 2>&1 \
  || fail "load generator reported a degraded run: $(tail -5 /tmp/smoke-loadgen.txt)"
ok "10k QPS for 3 s with no loss"

STATS="$(curl -sf "http://127.0.0.1:$ADMIN_PORT/stats")"
python3 - "$STATS" <<'PY' || exit 1
import json, sys
d = json.loads(sys.argv[1])
def check(cond, msg):
    if not cond:
        print(f"SMOKE FAIL: {msg}", file=sys.stderr)
        print(json.dumps(d, indent=2), file=sys.stderr)
        sys.exit(1)
    print(f"  ok  {msg}")

check(d["requests"] > 25000, f"server handled {d['requests']} requests")
check(d["replies_sent"] > 25000, f"server sent {d['replies_sent']} replies")

# A real send error is always a bug. Transient back-pressure is not: on a
# platform without SO_REUSEPORT load balancing, workers share one socket and it
# occasionally refuses a send with EAGAIN. So those are held to a rate rather
# than to zero, and the two are distinguished so a genuine failure cannot hide
# behind the allowance.
check(d["send_errors"] == 0, "no hard send errors")
transient = d["send_wouldblock"] + d["send_nobufs"]
rate = transient / max(d["requests"], 1)
check(rate < 0.001,
      f"transient send drops {transient} ({rate*100:.4f}%) are within tolerance")
check(d["bad_magic"] == 0, "no protocol version mismatches")
v = d["verdicts"]
# A run where everything is allowed, or everything denied, means the policy or
# the roster is not what the test thinks it is.
check(v["allow"] > 0 and v["deny"] > 0 and v["redirect"] > 0,
      f"all three verdicts occurred: {v}")
check(0 < d["service_ns"]["p50"] < 50_000, f"service time p50 {d['service_ns']['p50']} ns is plausible")
check(d["policy_version"] >= 1, "a policy version is live")
PY

# --- operational surface ---------------------------------------------------
curl -sf "http://127.0.0.1:$ADMIN_PORT/metrics" | grep -q "policy_requests_total" \
  || fail "/metrics is missing policy_requests_total"
ok "/metrics exposes Prometheus counters"

curl -sf "http://127.0.0.1:$ADMIN_PORT/rules" | grep -q '"sha256"' \
  || fail "/rules is missing the source fingerprint"
ok "/rules reports the compiled policy"

IMSI="$(sed -n '2p' config/subscribers.csv | cut -d, -f1)"
curl -sf "http://127.0.0.1:$ADMIN_PORT/subscriber/$IMSI" | grep -q "$IMSI" \
  || fail "/subscriber/$IMSI did not return that subscriber"
ok "/subscriber/{imsi} works"

curl -sf "http://127.0.0.1:$ADMIN_PORT/explain?imsi=$IMSI&dnn=internet" | grep -q "features_decoded" \
  || fail "/explain did not return a decoded feature word"
ok "/explain works"

# --- HTTP front: same decision, different wire ------------------------------
HTTP_BODY="$(curl -sf "http://127.0.0.1:$HTTP_PORT/v1/decide?imsi=$IMSI&dnn=internet&rat=NR")" \
  || fail "the HTTP front did not answer"
echo "$HTTP_BODY" | grep -q '"verdict"' || fail "HTTP front returned no verdict: $HTTP_BODY"
echo "$HTTP_BODY" | grep -q '"policy_version"' || fail "HTTP front omitted the policy version"
ok "HTTP front answers GET /v1/decide"

# No -f here: --fail makes curl suppress its output for a 4xx, which is exactly
# the response this check is trying to read.
curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/v1/decide" 2>/dev/null \
  | grep -q '^400$' || fail "a request with no IMSI should be a 400"
ok "HTTP front rejects a malformed request with 400"

"$LOADGEN" --server "127.0.0.1:$HTTP_PORT" --protocol http --connections 16 \
           --qps 5000 --duration 3 --warmup 1 --threads 1 --no-pin --timeout-ms 500 \
           > /tmp/smoke-http.txt 2>&1 \
  || fail "the HTTP front lost requests under load: $(tail -5 /tmp/smoke-http.txt)"
ok "5k QPS over HTTP for 3 s with no loss"

# --- hot reload while traffic is flowing -----------------------------------
"$LOADGEN" --server "127.0.0.1:$PORT" --qps 10000 --duration 4 --warmup 0 \
           --threads 1 --no-pin --timeout-ms 500 > /tmp/smoke-reload.txt 2>&1 &
LOADGEN_PID=$!
sleep 0.5
for _ in 1 2 3 4 5; do
  curl -sf -X POST "http://127.0.0.1:$ADMIN_PORT/rules/reload" >/dev/null || fail "reload failed"
  sleep 0.4
done
wait $LOADGEN_PID || fail "traffic was degraded across reloads: $(tail -5 /tmp/smoke-reload.txt)"
ok "5 hot reloads under load, no dropped requests"

FINAL="$(curl -sf "http://127.0.0.1:$ADMIN_PORT/stats")"
python3 - "$FINAL" <<'PY' || exit 1
import json, sys
d = json.loads(sys.argv[1])
r = d["reload"]
if r["failures"] != 0:
    print(f"SMOKE FAIL: {r['failures']} reload(s) failed: {r['last_error']}", file=sys.stderr)
    sys.exit(1)
if d["policy_version"] < 6:
    print(f"SMOKE FAIL: policy version is {d['policy_version']}, expected at least 6", file=sys.stderr)
    sys.exit(1)
print(f"  ok  policy version advanced to {d['policy_version']} with no failed reloads")
PY

# --- shutdown --------------------------------------------------------------
kill -TERM "$SERVER_PID"
for _ in $(seq 1 40); do
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.25
done
kill -0 "$SERVER_PID" 2>/dev/null && fail "server did not exit on SIGTERM"
SERVER_PID=""
ok "clean shutdown on SIGTERM"

echo "smoke test passed ($BACKEND)"
