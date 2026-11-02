#!/bin/bash
# Apply SAML authentication configuration to a target env directory.
# Copies your IdP signing certificate into envs/certs/ (shared) and the target
# env, switches auth_mode to "saml" in config.toml, and substitutes
# $AZURE_TENANT and the SP domain placeholders in config/saml.json.
# Optional env: SAML_IDP_CERT (cert path), SAML_SP_ENTITY_ID (SP entity ID).
#
# Usage:
#   ./scripts/_saml-setup.sh <target_dir> <azure_tenant>
# Example:
#   ./scripts/_saml-setup.sh envs/local-name 00000000-0000-0000-0000-000000000000

set -e

source "$(dirname "$0")/_env.sh"
source "$(dirname "$0")/_portable.sh"

# Values the sourced helpers above must provide.
: "${envs_dir:?_env.sh must set envs_dir}"

target_dir="${1:?target_dir required (e.g. envs/local-name)}"
azure_tenant="${2:?AZURE_TENANT required — pass as: make run-debug auth=saml AZURE_TENANT=<tenant-guid>}"

# Read public hostname from agent-stream.json (set during _prepare.sh).
domain_url=$(jq -r '[.. | objects | select(has("external_origin")) | .external_origin] | first // empty' \
  "${target_dir}/config/agent-stream.json" 2>/dev/null || true)
domain_host=""
if [[ -n "${domain_url}" && "${domain_url}" != "null" ]]; then
  domain_host="${domain_url#*://}"   # strip scheme
  domain_host="${domain_host%%/*}"   # strip path and trailing slash
fi

saml_json="${target_dir}/config/saml.json"
saml_idp_cert_path="certs/saml-idp.cer"
legacy_idp_cert_path="certs/entra-fabric-sso.cer"

# Apply a jq filter to saml.json in place (rewrites contents, keeps file mode).
saml_json_set() {
  local tmp
  tmp="$(mktemp)"
  if ! jq "$@" "${saml_json}" > "${tmp}"; then
    rm -f "${tmp}"
    echo "❌ Failed to update ${saml_json}" >&2
    exit 1
  fi
  cat "${tmp}" > "${saml_json}"
  rm -f "${tmp}"
}

# Envs created before the cert rename still point idp_cert_path at the removed
# Entra cert (_prepare.sh never overwrites an existing saml.json). Migrate that
# value, and refuse any other path: this script only installs saml-idp.cer, so
# the supplied certificate would otherwise be silently ignored.
current_idp_cert_path="$(jq -r '.idp_cert_path // empty' "${saml_json}")"
case "${current_idp_cert_path}" in
  "${saml_idp_cert_path}") ;;
  "${legacy_idp_cert_path}")
    saml_json_set --arg p "${saml_idp_cert_path}" '.idp_cert_path = $p'
    echo "✅ Migrated idp_cert_path → ${saml_idp_cert_path}"
    ;;
  *)
    echo "❌ ${saml_json} has idp_cert_path=\"${current_idp_cert_path}\", but this script installs" >&2
    echo "   the IdP certificate at ${saml_idp_cert_path}. Set idp_cert_path to that value." >&2
    exit 1
    ;;
esac

# 1. Copy the IdP cert into the shared envs/certs/ directory on every explicit
# `auth=saml` run, so a rotation rolls out to every env. For Microsoft Entra
# this is the app's per-application "Federated SSO Certificate" (Enterprise
# Applications > your app > Single sign-on > SAML Certificates > Certificate
# (Base64)), not the tenant-wide federation metadata certs. Place it at
# config/certs/saml-idp.cer (gitignored), or point SAML_IDP_CERT at it. The
# copied filename matches idp_cert_path in config/examples/saml.example.json.
idp_cert="${SAML_IDP_CERT:-$(pwd)/config/certs/saml-idp.cer}"
if [[ ! -f "${idp_cert}" ]]; then
  echo "❌ SAML IdP certificate not found at ${idp_cert}" >&2
  echo "   Download your IdP's SAML signing certificate (Base64) and save it at" >&2
  echo "   config/certs/saml-idp.cer, or set SAML_IDP_CERT=<path>." >&2
  exit 1
fi
mkdir -p "${envs_dir}/certs"
local_cert="${envs_dir}/certs/saml-idp.cer"
# cp -f: a prior run left these read-only, so force-overwrite instead of failing.
cp -f "${idp_cert}" "${local_cert}"
chmod 0400 "${local_cert}"
echo "✅ IdP certificate → envs/certs/saml-idp.cer"

# 2. Copy cert into the target env certs/ so the appliance can read it at startup.
mkdir -p "${target_dir}/certs"
cp -f "${local_cert}" "${target_dir}/certs/saml-idp.cer"
cp -f "${envs_dir}/certs/key.pem" "${target_dir}/certs/saml-sp-key.pem"
cp -f "${envs_dir}/certs/cert.pem" "${target_dir}/certs/saml-sp-cert.pem"
# Restrict the copied key material: the SP private key is owner-read-only.
chmod 0400 "${target_dir}/certs/saml-idp.cer" "${target_dir}/certs/saml-sp-key.pem"
chmod 0444 "${target_dir}/certs/saml-sp-cert.pem"
# Drop the pre-rename Entra cert so it can't be mistaken for the trusted one.
rm -f "${envs_dir}/certs/entra-fabric-sso.cer" "${target_dir}/certs/entra-fabric-sso.cer"

# 3. Swap _storage/passkeys before changing auth_mode.
"$(dirname "$0")/_swap-auth-storage.sh" "${target_dir}" "saml"

# 4. Switch auth_mode to "saml" in config.toml (idempotent).
sedi 's/auth_mode = "passkey"/auth_mode = "saml"/' "${target_dir}/config/config.toml"

# 5. Substitute $AZURE_TENANT placeholder in saml.json (idempotent — no-op if already replaced).
# The trusted signing cert belongs to one IdP application: the tenant must own
# the app whose certificate you supplied, or every SAML response fails signature
# verification at runtime.
sedi "s|\\\$AZURE_TENANT|${azure_tenant}|g" "${saml_json}"

# 6. Replace the template SP domain in sp_acs_url and sp_entity_id (idempotent).
#    sp_entity_id is checked against the assertion audience, so it must equal the
#    Identifier (Entity ID) registered with your IdP. The default is
#    https://<domain>/api/saml/metadata; set SAML_SP_ENTITY_ID if you registered
#    a different identifier. Values already set in saml.json are left as-is.
if [[ -n "${domain_host}" ]]; then
  sedi "s|YOUR_DOMAIN|${domain_host}|g" "${saml_json}"
fi
if [[ -n "${SAML_SP_ENTITY_ID:-}" ]]; then
  saml_json_set --arg id "${SAML_SP_ENTITY_ID}" '.sp_entity_id = $id'
fi

# 7. Fail rather than report success with placeholders the appliance reads.
if grep -qE 'YOUR_DOMAIN|\$AZURE_TENANT' "${saml_json}"; then
  echo "❌ ${saml_json} still contains template placeholders:" >&2
  grep -nE 'YOUR_DOMAIN|\$AZURE_TENANT' "${saml_json}" >&2
  echo "   Set external_origin in ${target_dir}/config/agent-stream.json, or edit saml.json directly." >&2
  exit 1
fi
sp_entity_id="$(jq -r '.sp_entity_id' "${saml_json}")"
sp_acs_url="$(jq -r '.sp_acs_url' "${saml_json}")"
echo "✅ SAML configured: tenant=${azure_tenant}, sp_entity_id=${sp_entity_id}, sp_acs_url=${sp_acs_url}"

# ──────────────────────────────────────────────────────────────────────────────
# Show the IdP registration values once per env, and again whenever they change.
_sp_notice_marker="${target_dir}/.saml_entra_notice_shown"
_sp_notice_values="${sp_entity_id} ${sp_acs_url}"
if [[ "$(cat "${_sp_notice_marker}" 2>/dev/null)" != "${_sp_notice_values}" ]]; then
  _BOLD=$'\033[1m'
  _CYAN=$'\033[0;36m'
  _YELLOW=$'\033[1;33m'
  _NC=$'\033[0m'
  echo ""
  echo "${_YELLOW}╔══════════════════════════════════════════════════════════════════╗${_NC}"
  echo "${_YELLOW}║  ⚠️   ACTION REQUIRED — Register these values in your identity   ║${_NC}"
  echo "${_YELLOW}║       provider's SAML application:                               ║${_NC}"
  echo "${_YELLOW}╚══════════════════════════════════════════════════════════════════╝${_NC}"
  echo ""
  echo "  Identifier (Entity ID):"
  echo "${_BOLD}${_CYAN}  ${sp_entity_id}${_NC}"
  echo "  Reply URL (Assertion Consumer Service URL):"
  echo "${_BOLD}${_CYAN}  ${sp_acs_url}${_NC}"
  echo ""
  if [[ -t 0 ]]; then
    read -r -p "Press Enter once these values are registered..." _
  fi
  printf '%s' "${_sp_notice_values}" > "${_sp_notice_marker}"
fi
