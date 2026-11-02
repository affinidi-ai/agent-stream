# Encryption at Rest

How Agent Stream encrypts sensitive storage records at rest, what each key source
requires, and how backups stay portable across nodes and key sources. For operator
guidance, use the hosted
[backup and encryption reference](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-stream/reference/configuration/backup-and-encryption/).

Implemented in [`src/encryption/`](../src/encryption/) and
[`src/backup_restore/`](../src/backup_restore/). The complete, commented configuration
is in [`config/examples/config.example.toml`](../config/examples/config.example.toml)
under `[encryption]`.

## Overview

Sensitive storage records are **encrypted at rest** with AES-256-GCM before they
touch disk. Encryption is a **required choice**: startup fails until `[encryption]`
either enables it or explicitly opts out (see
[Choosing encryption or plaintext](#choosing-encryption-or-plaintext)).
The data keys can come from a local master key (`environment` / `file`) or from
**AWS KMS**, which mints a **fresh data key per value** and keeps no long-lived key
in memory. Backups are made **portable**: on export, encrypted values are
decrypted, then the whole archive is sealed with a separate **Backup Encryption
Key (BEK)** so it restores on any node that holds the BEK — independent of the
source node's key source.

## Keys at a glance

| Key | What it protects | Where it lives | Scope |
| --- | --- | --- | --- |
| **MEK** (Master Encryption Key) | The stored values, under `environment` / `file` | Env var or key file (32 bytes) | Per node |
| **CMK** (AWS KMS key) | The per-value data keys, under `aws_kms` | AWS KMS; never leaves KMS | Governed by KMS + IAM |
| **DEK** (Data Encryption Key) | The value bytes | Stored inside each `ENC[...]` value (KMS-wrapped under `aws_kms`, minted fresh per value) | Per encrypted value |
| **BEK** (Backup Encryption Key) | A whole backup archive | Config (`backup_encryption_key`) | Portable across nodes with matching `did.domain` |

The on-disk form is `ENC[version:...]`. `version = 1` is a local-MEK envelope
(`environment` / `file`); `version = 2` is the AWS KMS per-value envelope. Reads
dispatch on the version, and a value written under one key source **cannot** be
read under the other — it fails closed with a clear error.

## What gets encrypted

When `enabled = true`, whole storage JSON files are written as `.json.enc` (a
single `ENC[...]` envelope over the entire record). This covers the sensitive
stores — agent DID / DIDComm private keys,
JWT-bearer strategies, OAuth identifiers and credential-provider secrets,
integration credentials and template variables, delegation-vault / operator
secrets, and connection-point secrets. Reads are backward compatible: a
non-`ENC[` value is treated as plaintext, so pre-existing files keep loading.
With encryption enabled, a plaintext record is migrated to `.json.enc` as it is
loaded on boot (encrypt-then-delete), and every new write is encrypted. A record
found only as plaintext, for example after a portable restore, goes through the
same schema migration as any other record before it is encrypted, so the
encrypted copy holds the current shape. A record that fails migration, or that
the migration retires (such as a Surface of a removed type), is not encrypted and
its plaintext file is left as it is
([`load_and_encrypt_raw_entity`](../src/storage/filesystem.rs)). No
plaintext copy is kept once encryption is enabled. A plaintext `.json` found beside
its `.json.enc` is deleted at boot without being applied, so make changes through
the API rather than by editing plaintext files.

With `field_encryption_enabled = true`, annotated sensitive fields are
additionally sealed as `ENC[...]` inside the (otherwise readable) JSON document,
on top of whole-file encryption. Public DID logs and documents stay plaintext by
design, and so does the revocation status list (`status_list.json` beside the appliance
DID), which maps agent DIDs to their status-list indexes.

Usage counters (`storage_paths.team_usage`, `storage_paths.surface_usage`) are written
as plaintext JSON. They hold Surface, Member and Team ids with spend and token
counts.

## Choosing encryption or plaintext

Every deployment must make an explicit choice in `[encryption]`
([`EncryptionConfig::validate`](../src/config/encryption_config.rs)):

| `[encryption]` | Startup |
| --- | --- |
| `enabled = true` with a `key_source` | Starts encrypted. A missing or invalid key still fails closed. |
| `allow_unencrypted = true` | Starts, storing data unencrypted. |
| Neither, including a table that only says `enabled = false`, or no table | Refused: `Encryption at rest is not configured`, naming both options. |
| Both `enabled = true` and `allow_unencrypted = true` | Refused as contradictory. |

`enabled = false` on its own is not an opt-out, because older generated and example
configurations carried it without anyone choosing plaintext. `--generate-bootstrap`
and the Docker quickstart write `enabled = true` with `key_source = "environment"`
and `key_env_var = "AS_MASTER_KEY"`; the quickstart generates the key into
`envs/master_key`. To keep an existing
plaintext deployment unencrypted, add `allow_unencrypted = true`. To encrypt it
instead, set `enabled = true` and a key source: records in the storage backends and
key files are encrypted as they load on the next boot (see
[What gets encrypted](#what-gets-encrypted)). Governance record logs
(`records.jsonl`, `signing-keys.jsonl`) and multimedia attachments written
unencrypted are **not** migrated: once encryption is on they are skipped as
unreadable and the governance chain reports as broken. Keep
`allow_unencrypted = true` on an appliance that already holds Governance Records
or attachments until they can be migrated.

## Config

```toml
[encryption]
# Required choice: enabled = true here, or allow_unencrypted = true instead.
# When on, storage files are written .json.enc.
enabled = true

# Key source: "environment", "file", or "aws_kms".
key_source = "aws_kms"

# For key_source = "aws_kms": per-value envelope encryption. Every value is sealed
# with a fresh KMS data key (GenerateDataKey on write, Decrypt on read).
kms_key_id = "<kms-key-arn>"
kms_max_concurrent_ops = 16   # optional, bounds in-flight KMS calls (default 16)

# For key_source = "environment": env var holding the 32-byte master key (hex/base64).
# The default variable name is AS_MASTER_KEY.
# Its previous names, AGENT_STREAM_MASTER_KEY and TRUST_GATEWAY_MASTER_KEY, are still
# read, in that order, when AS_MASTER_KEY is unset.
# key_env_var = "AS_MASTER_KEY"
# For key_source = "file": path to the 32-byte master key file.
# key_file = "certs/master.key"

# Additionally seal annotated fields as ENC[...] inside the JSON document.
field_encryption_enabled = false
```

```toml
# TOP-LEVEL key — NOT under [encryption] (it would be silently ignored).
# Runtime environment injection is recommended for managed deployments.
# The resolved value must be 64 hex chars = 32-byte AES-256 key.
backup_encryption_key = "env://AS_BACKUP_ENCRYPTION_KEY"
```

When encryption is enabled, a missing or invalid key **fails startup closed** —
the service never silently falls back to plaintext.

## What `aws_kms` requires

| Requirement | Detail |
| --- | --- |
| A symmetric KMS key | Named by `kms_key_id` (key id or ARN). A missing `kms_key_id` aborts startup. |
| `kms:GenerateDataKey` and `kms:Decrypt` on that key | Granted to the workload's ambient identity. No static cloud keys are configured. |
| A top-level `backup_encryption_key` | Required for backup and restore under every key source; see below. |
| A store written under `aws_kms`, or an empty one | A populated store written under another key source must be migrated first; see [Changing the key source](#changing-the-key-source). |

### Runtime behavior under `aws_kms`

- **Write:** `kms:GenerateDataKey(kms_key_id, AES_256)` returns a fresh 32-byte
  plaintext key plus its CMK-wrapped ciphertext; AES-256-GCM encrypts the value;
  the plaintext key is zeroized immediately (no reuse, no cache). On-disk:
  `ENC[2:<wrapped key>:<ciphertext>]`.
- **Read:** `kms:Decrypt` recovers the wrapped key, AES-256-GCM decrypts, key is
  zeroized.
- **Concurrency:** in-flight KMS calls are bounded by `kms_max_concurrent_ops`
  (default 16). Encryption is on the serialization hot path, so boot cost scales
  with the encrypted-file count and a KMS outage degrades request handling, not
  just boot. Size `kms_max_concurrent_ops` against real record/file counts in
  staging.
- **Observability:** `agent_stream_kms_operation_total{op,result}` and the
  `agent_stream_kms_operation_duration_seconds{op}` histogram.
- **Cost:** every encrypted read and write is a billed KMS request.

## Fail-closed behavior

Encryption never degrades to plaintext silently:

- **Missing / invalid key at startup** aborts boot. Under `aws_kms`, a missing
  `kms_key_id` aborts boot.
- **Any KMS error at runtime** (throttle after retries, `AccessDenied`, network,
  wrong CMK, non-32-byte key) fails the affected read or write closed — never a
  plaintext fallback.
- **Encrypted files with encryption off:** if `allow_unencrypted = true` but
  `.json.enc` files remain from a prior run, they cannot be decrypted and are never
  served as plaintext. The bespoke stores (DID / DIDComm key files) reject them with
  an explicit error; the generic storage backend skips the encrypted-only record
  (it is absent until encryption is re-enabled). Re-enable encryption — or migrate
  those records back to plaintext — before opting out with `allow_unencrypted = true`.

## Changing the key source

Switching `key_source` on a populated store (for example `environment` → `aws_kms`,
or rotating to a different CMK family) leaves previously written values
unreadable: a `version = 1` local-MEK value cannot be read under `aws_kms`, and a
`version = 2` KMS value cannot be read under a local MEK.

To prevent a half-readable store, a **boot preflight** scans the storage root and
**refuses to start** — naming the offending file — if any stored envelope version
is incompatible with the active `key_source`. There is no automatic batch
re-encryption. To change key source on existing data, migrate first:

1. Take a **portable backup** under the current key source (see below).
2. Point the node at the new `key_source` and a **fresh `_storage`**.
3. **Restore** the backup; records are schema-migrated and re-encrypted under the
   new key on the next boot.

## Backups

Portable backups decouple from the node's encryption-at-rest key. On export,
every encrypted value is decrypted to plaintext inside the archive, then the
whole archive is sealed with the `backup_encryption_key`.

| Route | Purpose |
| --- | --- |
| `POST /v1/admin/backup-storage` | Create an encrypted backup of the whole storage folder, returned as `backup.asbak` |
| `POST /v1/admin/restore-storage` | Restore an encrypted backup |
| `POST /v1/debug/export-storage` | Export storage |

All three require `storage.admin` (`administrator`; see [`RBAC.md`](RBAC.md)) and are
mounted only when an authentication backend exists. At startup, a `backup.asbak` found
in `storage_paths.backup_restore` (default `../_backup_restore`) is restored before the
stores open. Backups taken before the file was renamed are still accepted: the dashboard
uploads `.tgwbak` files, and a staged `backup.tgwbak` is restored when no `backup.asbak`
is present. Both staged files are removed after a successful restore.

### Backup encryption key

- **Configure an explicit BEK.** `backup_encryption_key` is a required top-level
  config key. It accepts `env://VAR` (recommended), `file://path`, or a literal
  64-character hex key resolving to 32 bytes. It must **not** be nested under
  `[encryption]`. Direct `aws_secrets://` and `aws_parameter_store://` references
  are unsupported; inject managed secret values into the runtime environment.
- Backup and encrypted restore **fail closed** without a valid BEK for every
  encryption-at-rest key source. There is no compiled-in fallback key.
- Every backup contains an AES-GCM-authenticated v2 manifest identifying
  product `agent-stream`, creation time, and canonical effective `did.domain`.
  A migrated legacy archive also carries authenticated `legacy_import: true`
  provenance. Restore rejects another product or domain before changing storage.
  Domain canonicalization accepts DNS names (including IDNs and an optional
  development port) but rejects IP literals. Startup restore rejects every
  plaintext archive; API restore publishes the authenticated encrypted staging
  file atomically.
- Backup creation fails rather than returning an archive larger than 64 MiB.
  API and startup restore reject larger encrypted archives before buffering the
  complete input. ZIP validation allows up to 100,000 entries,
  128 MiB per uncompressed entry, 512 MiB total expanded data, a 200:1 maximum
  per-entry compression ratio, and a 64 KiB manifest. It fully validates and
  extracts into staging before changing `_storage`; installation failure triggers
  rollback from the temporary pre-restore snapshot, which is deleted after success.
- Domain binding prevents cross-domain restore but does not prove ownership of
  the domain. Recovering onto a replacement appliance may require restoring the
  original domain first.
- **A wrong or tampered BEK** fails restore closed (AES-GCM authentication).
- Scope a BEK to one product and environment.
- Temporary migration accepts up to four ordered, comma-separated previous BEKs.
  Configure `legacy_backup_encryption_keys =
  "env://AS_LEGACY_BACKUP_KEYS"` (or a `file://`/literal source). A
  valid non-empty resolved value enables decrypt-only compatibility; an explicitly
  configured empty or invalid source fails startup, while the environment variable
  alone is ignored without the TOML source. Current and legacy
  sources are resolved at process startup, so secret rotation requires a
  task/process restart. After a legacy restore, create a fresh backup immediately
  and remove both the TOML field and runtime value.
- Structured `audit` events record API user or startup-system actor, restore
  path, current/legacy key class, domain metadata, and outcome without recording
  key values or decrypted content.
- **Guard the BEK like the CMK.** Anyone with a product/environment BEK can
  authenticate archives in that scope. Store it in a secrets manager.

## Failure and recovery

- **Key durability.** Data is recoverable only as long as the key survives. Back
  up / replicate the CMK and its key policy (or the local MEK). If the key is lost
  and no copy exists, encrypted data is unrecoverable. Rotate and audit via KMS +
  CloudTrail.
- **KMS unreachable at boot** aborts startup rather than running unprotected.
- **Portable export requires a key source.** A record that cannot be decrypted on
  export (no/wrong key, corrupt envelope) is kept verbatim with a loud warning —
  the export never aborts and never drops data, but the archive is not portable
  until a key source is configured.

## Related

- [`CONFIGURATION_REFERENCE.md`](CONFIGURATION_REFERENCE.md): `[encryption]`,
  `backup_encryption_key`, and `storage_paths`.
- [`RBAC.md`](RBAC.md): `storage.admin`.
- [`TERMS_AND_CONSENT.md`](TERMS_AND_CONSENT.md): Terms state carried in backups.
- [`OBSERVABILITY.md`](OBSERVABILITY.md): KMS metrics and `audit` events.
