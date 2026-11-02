#!/usr/bin/env bash
# End-to-end testkit entry point.
#
# Usage:
#   ./run.sh -host <appliance-url>            # external mode (default)
#   ./run.sh external -host <appliance-url>   # same, explicit
#   ./run.sh managed                          # self-hosted appliance (docker)
#   ./run.sh -conformance -host <url>         # real-API conformance suite only
#
# EXTERNAL mode drives an appliance you run yourself (so you can watch its UX).
# It starts only the mock LLM + the runner on the host and points them at the
# URL you pass with -host. THERE IS NO DEFAULT HOST — you must pass -host so it
# is never ambiguous which appliance is being driven. Your running appliance
# must:
#   * be reachable at the -host URL,
#   * have the standalone Mock LLM provider (enum_value: mock_llm) with the
#     mock-small / mock-large models in its custom catalog
#     (_storage/llm_configuration/custom_llm.json; the catalog hot-reloads with
#     no restart),
#   * be able to reach the host mock at $MOCK_INTERNAL_URL (default
#     http://localhost:9000),
#   * either be in debug test-auth mode (AS_TEST_MODE=true + AS_TEST_TOKEN),
#     or you pass APPLIANCE_SESSION_TOKEN=<admin session>.
#
# MANAGED mode brings up the mock LLM + a throwaway DEBUG appliance + the runner
# entirely in docker-compose (no external instance needed). It uses the internal
# compose URL, so -host does not apply.
#
# Exits with the runner's exit code (0 = appliance stats matched the locally
# tracked stats; non-zero = mismatch or error). The retained run report is left
# under ./results/.
set -euo pipefail

cd "$(dirname "$0")"

usage() {
  cat >&2 <<'EOF'
usage: ./run.sh [external|managed] -host <appliance-url> [load/drill options]

  external (default)  drive an appliance you run yourself; -host is REQUIRED
  managed             self-host a throwaway appliance via docker-compose

  -host <url>         appliance base URL to drive (external mode), e.g.
                      -host http://localhost:8280 . No default — must be given.

  -conformance        run ONLY the real-API conformance suite (dialect + endpoint
                      conformance against real OpenAI/Anthropic keys resolved by
                      tag) instead of the mock load/reconciliation test. Requires
                      -host. No mock LLM is started.

  -load <level>       overall traffic intensity: small | medium | large
                      (default medium = the historical defaults).
                        small  lightweight & short-lived (tiny population,
                               a few dozen calls, low concurrency).
                        medium current behaviour.
                        large  HAMMER the appliance — big population, thousands
                               of calls, deep concurrency (many connections to
                               the SAME surface at once) and repeated calls from
                               the SAME member, for maximum throughput.
                      Individual knobs below still override the chosen level.

  load shaping (the general-traffic phase of each round):
    -concurrency <n>  max in-flight requests (default 1 = serial)
    -rps <n>          target dispatch rate, requests/sec (default 0 = unlimited)
    -duration <secs>  run the load phase for this long instead of a fixed count
    -requests <n>     number of load requests per round (default 300)

  drills:
    -no-cap-drill         skip the member/team quota enforcement drill
    -no-rejection-drill   skip the judge/jury rejection drill
    -no-policy-drill      skip the OPA policy enforcement drill
    -no-enrolment-drill   skip the member auto-provisioning (enrolment) drill
    -no-enrolment-guardrail
                          skip the round-1 enrolment guardrail sub-scenario
    -enrolment-mtls-optional
                          downgrade "mTLS must be exercised" from a hard failure
                          to a logged skip (e.g. an external appliance not
                          configured to trust the runner as a forwarded proxy)
    -enrolment-calls <n>  priced calls per enrolled member per round
    -no-interactive       run one round then tear down (CI mode)

  -h, --help          show this help

examples:
  ./run.sh -host http://localhost:8280
  ./run.sh -host http://localhost:8280 -load small
  ./run.sh -host http://localhost:8280 -load large -no-interactive
  ./run.sh -host http://localhost:8280 -concurrency 16 -rps 50 -duration 60
  ./run.sh external -host https://my-appliance.local:8280 -requests 1000
  ./run.sh managed
EOF
}

MODE=""
HOST=""
CONFORMANCE=""

while [ $# -gt 0 ]; do
  case "$1" in
    -host|--host)
      shift
      [ $# -gt 0 ] || { echo "error: -host requires a URL argument" >&2; usage; exit 64; }
      HOST="$1"
      ;;
    -host=*|--host=*)
      HOST="${1#*=}"
      ;;
    -load|--load)
      shift; [ $# -gt 0 ] || { echo "error: -load requires a level (small|medium|large)" >&2; exit 64; }
      export LOAD="$1" ;;
    -load=*|--load=*)
      export LOAD="${1#*=}" ;;
    -concurrency|--concurrency)
      shift; [ $# -gt 0 ] || { echo "error: -concurrency requires a number" >&2; exit 64; }
      export CONCURRENCY="$1" ;;
    -concurrency=*|--concurrency=*)
      export CONCURRENCY="${1#*=}" ;;
    -rps|--rps)
      shift; [ $# -gt 0 ] || { echo "error: -rps requires a number" >&2; exit 64; }
      export RPS="$1" ;;
    -rps=*|--rps=*)
      export RPS="${1#*=}" ;;
    -duration|--duration)
      shift; [ $# -gt 0 ] || { echo "error: -duration requires a number" >&2; exit 64; }
      export DURATION="$1" ;;
    -duration=*|--duration=*)
      export DURATION="${1#*=}" ;;
    -requests|--requests)
      shift; [ $# -gt 0 ] || { echo "error: -requests requires a number" >&2; exit 64; }
      export NUM_REQUESTS="$1" ;;
    -requests=*|--requests=*)
      export NUM_REQUESTS="${1#*=}" ;;
    -no-cap-drill|--no-cap-drill)
      export CAP_DRILL="false" ;;
    -no-rejection-drill|--no-rejection-drill)
      export REJECTION_DRILL="false" ;;
    -no-policy-drill|--no-policy-drill)
      export POLICY_DRILL="false" ;;
    -no-enrolment-drill|--no-enrolment-drill)
      export ENROLMENT_DRILL="false" ;;
    -no-enrolment-guardrail|--no-enrolment-guardrail)
      export ENROLMENT_GUARDRAIL="false" ;;
    -enrolment-mtls-optional|--enrolment-mtls-optional)
      export ENROLMENT_MTLS="optional" ;;
    -enrolment-calls|--enrolment-calls)
      shift; [ $# -gt 0 ] || { echo "error: -enrolment-calls requires a number" >&2; exit 64; }
      export ENROLMENT_CALLS="$1" ;;
    -enrolment-calls=*|--enrolment-calls=*)
      export ENROLMENT_CALLS="${1#*=}" ;;
    -no-interactive|--no-interactive)
      export INTERACTIVE="false" ;;
    -conformance|--conformance)
      CONFORMANCE=1 ;;
    external|managed)
      MODE="$1"
      ;;
    -h|--help)
      usage; exit 0
      ;;
    *)
      echo "error: unknown argument '$1'" >&2; usage; exit 64
      ;;
  esac
  shift
done

MODE="${MODE:-external}"

if [ -n "${LOAD:-}" ]; then
  case "${LOAD}" in
    small|medium|large) ;;
    *) echo "error: -load must be one of: small, medium, large (got '${LOAD}')" >&2; usage; exit 64 ;;
  esac
fi

if [ "$MODE" = "external" ] && [ -z "$HOST" ]; then
  echo "error: external mode requires -host <appliance-url> (there is no default)" >&2
  usage
  exit 64
fi

if [ -n "$CONFORMANCE" ] && [ "$MODE" = "managed" ]; then
  echo "error: -conformance runs against a real appliance (external, with real provider keys); managed mode is not supported" >&2
  exit 64
fi

if [ "$MODE" = "managed" ] && [ -n "$HOST" ]; then
  echo "warning: -host is ignored in managed mode (the appliance runs in docker)" >&2
fi

# Track the mock LLM PID at script scope so the EXIT trap can reach it after
# run_external() has returned (a function-local would be out of scope by then).
MOCK_PID=""
trap 'if [ -n "${MOCK_PID:-}" ]; then kill "${MOCK_PID}" >/dev/null 2>&1 || true; fi' EXIT

# True if something is already listening on the given TCP port (bash /dev/tcp).
port_in_use() {
  local port="$1"
  (exec 3<>"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1 || return 1
  exec 3>&- 3<&- 2>/dev/null || true
  return 0
}

run_managed() {
  local COMPOSE="docker compose"
  if ! docker compose version >/dev/null 2>&1; then
    COMPOSE="docker-compose"
  fi

  echo "==> [managed] Resetting prior managed testkit state…"
  $COMPOSE down --remove-orphans --volumes >/dev/null 2>&1 || true

  local build_started_at
  build_started_at=$(date +%s)
  echo "==> [managed] Building testkit images (debug appliance)…"
  $COMPOSE build
  echo "==> [managed] Image build duration: $(($(date +%s) - build_started_at))s"

  local suite_started_at
  suite_started_at=$(date +%s)
  echo "==> [managed] Running testkit (mock-llm + as1 + runner)…"
  set +e
  $COMPOSE up --abort-on-container-exit --exit-code-from runner
  local code=$?
  set -e
  echo "==> [managed] Test execution duration: $(($(date +%s) - suite_started_at))s"
  $COMPOSE logs --no-color > results/containers.log 2>&1 || true

  echo "==> [managed] Tearing down containers (results retained under ./results/)…"
  $COMPOSE down --remove-orphans --volumes >/dev/null 2>&1 || true
  return "$code"
}

run_external() {
  local APPLIANCE_URL="$HOST"
  local MOCK_PORT="${MOCK_LLM_PORT:-9000}"

  command -v node >/dev/null 2>&1 || { echo "node is required for external mode"; exit 3; }

  echo "==> [external] Target appliance: ${APPLIANCE_URL}"

  # Reuse an already-running mock if one is healthy on the port; otherwise the
  # port must be free so we can start (and own) our own.
  if curl -fsS "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1; then
    echo "==> [external] Reusing mock LLM already healthy on :${MOCK_PORT}"
  elif port_in_use "$MOCK_PORT"; then
    echo "error: port ${MOCK_PORT} is already in use by something that is not a healthy mock LLM." >&2
    echo "       free it (e.g. 'lsof -i :${MOCK_PORT}' then kill the process) or set MOCK_LLM_PORT=<free-port>." >&2
    exit 3
  else
    echo "==> [external] Starting mock LLM on :${MOCK_PORT}…"
    MOCK_LLM_PORT="$MOCK_PORT" node mock-llm/server.js &
    MOCK_PID=$!
    # Wait for the mock to answer health before driving traffic; bail early if
    # the process dies (e.g. it failed to bind the port).
    local ready=""
    for _ in $(seq 1 20); do
      if curl -fsS "http://localhost:${MOCK_PORT}/health" >/dev/null 2>&1; then ready=1; break; fi
      if ! kill -0 "$MOCK_PID" >/dev/null 2>&1; then break; fi
      sleep 0.5
    done
    if [ -z "$ready" ]; then
      echo "error: mock LLM failed to become healthy on :${MOCK_PORT} (it may have failed to start)." >&2
      exit 3
    fi
  fi

  echo "==> [external] Running runner against ${APPLIANCE_URL}…"
  set +e
  APPLIANCE_URL="$APPLIANCE_URL" node testkit/src/main.js
  local code=$?
  set -e
  return "$code"
}

# Conformance mode: drive the real-API dialect/endpoint conformance suite against
# the -host appliance. No mock LLM, no load/reconciliation — just the conformance
# checks. Provider keys are resolved on the appliance by tag.
run_conformance() {
  local APPLIANCE_URL="$HOST"
  command -v node >/dev/null 2>&1 || { echo "node is required for -conformance"; exit 3; }
  echo "==> [conformance] Target appliance: ${APPLIANCE_URL}"
  echo "==> [conformance] Running real-API conformance suite (no mock, no load)…"
  set +e
  APPLIANCE_URL="$APPLIANCE_URL" node testkit/src/conformance-main.js
  local code=$?
  set -e
  return "$code"
}

case "$MODE" in
  external) if [ -n "$CONFORMANCE" ]; then run_conformance; else run_external; fi; code=$? ;;
  managed)  run_managed;  code=$? ;;
  *) echo "unknown mode '$MODE' (use 'external' or 'managed')"; exit 64 ;;
esac

if [ "${code:-1}" -eq 0 ]; then
  echo "==> TESTKIT PASSED"
else
  echo "==> TESTKIT FAILED (exit ${code:-1})"
fi
exit "${code:-1}"
