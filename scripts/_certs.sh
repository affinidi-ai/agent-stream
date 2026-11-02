#!/bin/bash

# -x Print out all executed commands to the terminal.
# set -x

# -e  Exit immediately if a command exits with a non-zero status.
set -e

current_dir=$(pwd)
envs_dir=envs

(mkdir -p "${envs_dir}" && echo "✅ ${envs_dir} directory created") || echo "✅ ${envs_dir} directory exist"

# Generate a persistent local backup encryption key (hex, 32 bytes). The backup key
# is required at runtime; the Makefile reads this file into AS_BACKUP_ENCRYPTION_KEY so
# local backups/restores work seamlessly. This dev key is local-only (envs/ is gitignored).
backup_key_file="${AS_BACKUP_KEY_FILE:-${envs_dir}/backup_encryption_key}"
if [[ ! -s "${backup_key_file}" ]]
then
  mkdir -p "$(dirname "${backup_key_file}")"
  openssl rand -hex 32 > "${backup_key_file}"
  chmod 600 "${backup_key_file}"
  echo "🔑 Generated local backup encryption key (${backup_key_file})"
fi

# Generate a persistent local master key for encryption at rest (hex, 32 bytes). The
# generated config.toml enables encryption with key_source = "environment"; the Makefile
# and _env.sh read this file into AS_MASTER_KEY. Losing it makes the encrypted
# local storage unreadable. Local-only (envs/ is gitignored).
master_key_file="${AS_MASTER_KEY_FILE:-${envs_dir}/master_key}"
if [[ ! -s "${master_key_file}" ]]
then
  mkdir -p "$(dirname "${master_key_file}")"
  (umask 077 && openssl rand -hex 32 > "${master_key_file}")
  echo "🔑 Generated local encryption-at-rest master key (${master_key_file})"
fi

if [[ ! -f "${envs_dir}/certs/cert.pem" ]]
then
  cd "${envs_dir}"
  mkdir -p config/certs
  "${current_dir}/scripts/certs/generate-cert.sh"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain config/certs/cert.pem
  else
    echo "ℹ️  Generated the development certificate without changing the Linux trust store."
  fi
  rm -Rf certs && mv config/certs .
  rm -Rf config
fi
