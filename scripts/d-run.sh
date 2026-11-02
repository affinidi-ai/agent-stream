#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

source ./scripts/_env.sh

if [[ ! -d "${docker_env_dir}" ]]
then
  echo "❌ docker directory does not exist, pls run make config-docker to set up environments"
  exit 1
fi

# Mock OpenAI-protocol model server behind the seeded /llm/quickstart surface,
# matching the mock-llm service in docker-compose.yml (same image, settings and
# network alias). It is not published to the host.
mock_name="${agent_name}-mock-llm"

cleanup() {
  echo "Cleaning up..."
  docker container rm -f "${agent_name}" >/dev/null 2>&1 || true
  docker container rm -f "${mock_name}" >/dev/null 2>&1 || true
  echo "Cleanup done."
}
trap 'cleanup' SIGINT EXIT

# Ports are read from ${docker_env_dir}/config/agent-stream.json

http_port=$(jq -r '.listeners[] | select(.id == "http-listener") | .port' "${docker_env_dir}/config/agent-stream.json")
https_port=$(jq -r '.listeners[] | select(.id == "https-listener") | .port' "${docker_env_dir}/config/agent-stream.json")

# Publish every inbound listener the config defines. The HTTPS listener (8443)
# serves the dashboard where WebAuthn passkey login is pinned (external_origin),
# so it must be reachable from the host or login fails with an origin mismatch.
# Bind to loopback only, as docker-compose.yml does: the seeded quickstart
# surface has no caller authentication.
publish_args=()
[[ -n "${http_port}" && "${http_port}" != "null" ]] && publish_args+=("--publish=127.0.0.1:${http_port}:${http_port}")
[[ -n "${https_port}" && "${https_port}" != "null" ]] && publish_args+=("--publish=127.0.0.1:${https_port}:${https_port}")

docker network create agent-network 2>/dev/null || echo "Network agent-network already exists."

docker rm -f "${agent_name}" "${mock_name}" >/dev/null 2>&1 || true

docker run \
    --detach \
    --name="${mock_name}" \
    --network agent-network \
    --network-alias mock-llm \
    --user node \
    --security-opt no-new-privileges:true \
    --workdir /app \
    --volume="$(pwd)/tests/appliance/mock-llm:/app:ro" \
    --env MOCK_LLM_PORT=9000 \
    --env MOCK_LLM_MIN_MS=100 \
    --env MOCK_LLM_MAX_MS=400 \
    node:22.23.4-alpine node server.js >/dev/null

# A dashboard backup restore exits with code 1 twice: once after staging
# backup.asbak in _backup_restore, and once at the next start after applying
# it (or a legacy backup.tgwbak). Run again after such an exit, so the restore
# completes; any other exit (including a config error) ends the script.
staged_backups=(
  "${docker_env_dir}/_backup_restore/backup.asbak"
  "${docker_env_dir}/_backup_restore/backup.tgwbak"
)
staged_backup_state() {
  local state="" backup
  for backup in "${staged_backups[@]}"; do
    if [[ -f "${backup}" ]]; then state+=1; else state+=0; fi
  done
  echo "${state}"
}
for _ in 1 2 3; do
  had_staged_backup="$(staged_backup_state)"

  set +e
  docker run \
      --name="${agent_name}" \
      --interactive \
      --network agent-network \
      --add-host=localhost:host-gateway \
      --cpus="${DOCKER_CPUS:-2}" \
      --memory="${DOCKER_MEMORY:-512m}" \
      --volume="${docker_env_dir}/config:/app/config" \
      --volume="${docker_env_dir}/certs:/app/certs" \
      --volume="${docker_env_dir}/_storage:/app/_storage" \
      --volume="${docker_env_dir}/_backup_restore:/app/_backup_restore" \
      "${publish_args[@]}" \
      --env RUST_LOG="info" \
      --env AWS_ACCESS_KEY_ID \
      --env AWS_SECRET_ACCESS_KEY \
      --env AWS_SESSION_TOKEN \
      --env AWS_REGION \
      --env AS_BACKUP_ENCRYPTION_KEY \
      --env AS_MASTER_KEY \
      --workdir /app \
      "${tag}"
  status=$?
  set -e
  docker container rm -f "${agent_name}" >/dev/null 2>&1 || true

  has_staged_backup="$(staged_backup_state)"
  if [[ ${status} -eq 1 && "${had_staged_backup}" != "${has_staged_backup}" ]]; then
    echo "Restarting to complete the backup restore..."
    continue
  fi
  exit "${status}"
done
echo "❌ Agent Stream kept exiting during a backup restore; see the log above." >&2
exit 1
