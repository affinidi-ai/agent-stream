#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

envs_dir="$(pwd)/envs"
export envs_dir
export local_env_dir="${envs_dir}/local"
export docker_env_dir="${envs_dir}/docker"
export agent_name="agent-stream"
export WWW_DIR="${WWW_DIR:-www/default}"

export enable_docker=false
export tag="${TAG:-${agent_name}:local}"
# Numeric user the image runs as (USER in Dockerfile and Dockerfile.dev).
export container_uid=10001

export AS_BACKUP_ENCRYPTION_KEY="${AS_BACKUP_ENCRYPTION_KEY:-${AGENT_STREAM_BACKUP_ENCRYPTION_KEY:-$(cat "${envs_dir}/backup_encryption_key" 2>/dev/null || true)}}"
export AS_MASTER_KEY="${AS_MASTER_KEY:-${AGENT_STREAM_MASTER_KEY:-$(cat "${envs_dir}/master_key" 2>/dev/null || true)}}"

# Per-instance ports are derived from these bases by adding a stable offset
# (see scripts/_prepare.sh → assign_ports). Each local-* instance gets a
# unique (HTTP_PORT, HTTPS_PORT, OUTBOUND_PORT, FRONTEND_PORT) tuple persisted to
# ${target_dir}/instance.env so run scripts can source it directly.
export DEFAULT_HTTP_PORT=8080
export DEFAULT_HTTPS_PORT=8443
export DEFAULT_OUTBOUND_PORT=9000
export DEFAULT_FRONTEND_PORT=3002
