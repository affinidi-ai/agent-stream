#!/usr/bin/env bash
#
# Run the Playwright UI test suite against a freshly started local gateway.
#
# Steps:
#   1. Ensure debug env config is in place (calls scripts/_prepare.sh, which
#      also self-heals the dashboard static path to ${WWW_DIR}/build), and
#      allow the dashboard's own origin in its `cors`, so the WebSocket the
#      dashboard opens is accepted.
#   2. Build the debug gateway binary (incremental, so a no-op when current).
#   3. Ensure the React dashboard bundle is built and up-to-date. The
#      Playwright global-setup also checks freshness, but rebuilding here
#      keeps a single rebuild path and avoids a noisy nested make call.
#   4. Free port 8080 if a previous run is still bound to it.
#   5. Start the gateway with AS_TEST_MODE=true, wait until /dashboard
#      answers, run the suite, and kill the gateway on exit (success or
#      failure).
#
# Env overrides:
#   AS_BASE_URL    default http://localhost:8080
#   AS_TEST_TOKEN  default test-token-12345
#   AS_HTTP_PORT   default 8080
#   AS_SKIP_BUILD  if "true", skip cargo and UI builds (assume current)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_ROOT}"
source scripts/_env.sh

TEST_TOKEN="${AS_TEST_TOKEN:-test-token-12345}"
ENV_DIR="${AS_ENV_DIR:-envs/local-tests}"
GATEWAY_BIN="${REPO_ROOT}/target/debug/agent-stream"
GATEWAY_LOG="/tmp/agent-stream-ui-tests.log"

GATEWAY_PID=""
cleanup() {
    if [[ -n "${GATEWAY_PID}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
        echo "🧹 Stopping gateway (pid ${GATEWAY_PID})..."
        kill "${GATEWAY_PID}" 2>/dev/null || true
        wait "${GATEWAY_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# 1. Config
if [[ ! -f "${ENV_DIR}/config/config.toml" || ! -f "${ENV_DIR}/config/agent-stream.json" ]]; then
    echo "📦 First-time env setup..."
    if [[ "${AS_SKIP_BUILD:-false}" != "true" ]]; then
        cargo build --bin agent-stream
    fi
fi
./scripts/_prepare.sh debug "${ENV_DIR}" --auto-accept >/dev/null

# Source the ports assigned by _prepare.sh (deterministic offset for local-tests)
source "${ENV_DIR}/instance.env"
HTTP_PORT="${AS_HTTP_PORT:-${HTTP_PORT}}"
BASE_URL="${AS_BASE_URL:-http://localhost:${HTTP_PORT}}"

# The dashboard's WebSocket is accepted only from an origin in `cors` or the
# WebAuthn external origin, which _prepare.sh points at the frontend dev
# server. The suite opens the dashboard this gateway serves at BASE_URL.
dashboard_origin=$(sed -E 's#^([A-Za-z][A-Za-z0-9+.-]*://[^/]+).*#\1#' <<<"${BASE_URL}")
config_json="${ENV_DIR}/config/agent-stream.json"
if ! jq -e --arg origin "${dashboard_origin}" 'any((.cors // [])[]; . == $origin)' "${config_json}" >/dev/null; then
    jq --arg origin "${dashboard_origin}" '.cors = ((.cors // []) + [$origin])' "${config_json}" > "${config_json}.tmp"
    mv "${config_json}.tmp" "${config_json}"
fi

# 2. Gateway binary
if [[ "${AS_SKIP_BUILD:-false}" != "true" ]]; then
    echo "🔨 Building debug gateway..."
    cargo build --bin agent-stream
fi

# 3. UI bundle (Playwright global-setup also checks; this keeps logs tidy)
if [[ "${AS_SKIP_BUILD:-false}" != "true" ]]; then
    src_mtime=$(find ${WWW_DIR:-www/default}/src -type f -not -path '*/node_modules/*' -exec stat -f %m {} + 2>/dev/null | sort -nr | head -1 || echo 0)
    build_mtime=$(find ${WWW_DIR:-www/default}/build -type f -exec stat -f %m {} + 2>/dev/null | sort -nr | head -1 || echo 0)
    if [[ -z "${build_mtime}" || "${src_mtime}" -gt "${build_mtime:-0}" ]]; then
        echo "🛠️  UI bundle stale, running make www-rebuild..."
        make www-rebuild >/dev/null
    fi
fi

# 4. Free test ports from a previous crashed run
for p in "${HTTP_PORT}" "${HTTPS_PORT}" "${OUTBOUND_PORT}"; do
    if existing=$(lsof -ti:"${p}" 2>/dev/null); then
        if [[ -n "${existing}" ]]; then
            echo "⚠️  Port ${p} in use by pid(s) ${existing} — killing..."
            echo "${existing}" | xargs kill -9 2>/dev/null || true
        fi
    fi
done
sleep 0.5

# 5. Start gateway, wait for readiness
echo "🚀 Starting gateway in test mode (logs: ${GATEWAY_LOG})..."
(
    cd "${ENV_DIR}"
    AS_TEST_MODE=true \
    AS_TEST_TOKEN="${TEST_TOKEN}" \
    RUST_LOG="${RUST_LOG:-warn}" \
    "${GATEWAY_BIN}" --config config/config.toml \
        > "${GATEWAY_LOG}" 2>&1 &
    echo $! > /tmp/agent-stream-ui-tests.pid
)
GATEWAY_PID=$(cat /tmp/agent-stream-ui-tests.pid)

ready=0
for _ in $(seq 1 30); do
    if curl -fsS -o /dev/null "${BASE_URL}/dashboard" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.5
done
if [[ "${ready}" -ne 1 ]]; then
    echo "❌ Gateway did not become ready on ${BASE_URL}. Last log lines:"
    tail -30 "${GATEWAY_LOG}" || true
    exit 1
fi
echo "✅ Gateway ready"

# 6. Run Playwright
cd ui-tests
[[ -d node_modules ]] || npm install --silent
npx playwright install chromium --with-deps >/dev/null 2>&1 || true
rm -rf test_results/.auth test_results/latest

# Pin a single result directory for the whole run so workers don't each
# create their own timestamped folder.
export AS_RESULT_DIR="./test_results/result_$(date +%Y%m%d_%H%M%S)"

test_exit=0
AS_BASE_URL="${BASE_URL}" \
AS_ENV_DIR="${ENV_DIR}" \
AS_TEST_MODE=true \
AS_TEST_TOKEN="${TEST_TOKEN}" \
AS_SKIP_UI_BUILD=true \
npm run test:ui || test_exit=$?

if [[ "${test_exit}" -ne 0 ]] && [[ "${CI:-false}" != "true" ]]; then
    npx playwright show-report "${AS_RESULT_DIR}/html" >/dev/null 2>&1 &
    disown $!
    echo "📊 UI test report: http://localhost:9323 (background, run 'make ui-test-report' to reopen)"
fi

exit "${test_exit}"
