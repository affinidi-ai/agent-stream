# Scripts

Helper scripts behind the `Makefile`. Run them through their make targets (`make help`
lists every target); the scripts expect to be started from the repository root with the
environment the targets set up. Development workflow, environments and options such as
`x=`, `tk=1` and `auth=` are described in
[`docs/development/DEVELOPMENT.md`](../docs/development/DEVELOPMENT.md).

Files starting with `_` are internal helpers called by other scripts or targets.

## Local run and environment setup

| Script | What it does | Called by |
| --- | --- | --- |
| `_env.sh` | Shared variables: `envs/` paths, default ports (HTTP 8080, HTTPS 8443), image and container names | sourced by most scripts |
| `_portable.sh` | Portable shell helpers for Bash setup scripts | sourced by `_prepare.sh`, `_saml-setup.sh` and `_passkey-setup.sh` |
| `_certs.sh` | Creates the local TLS certificate (via `certs/generate-cert.sh`) and trusts it | `make config-certs` (and every target that depends on it) |
| `_prepare.sh` | Builds an environment directory (`envs/local`, `envs/local-<x>`, `envs/local-tests`, `envs/docker`) from `config/examples/`: config files, ports, certificates, dashboard path | `make config-debug`, `config-debug-dev`, `config-debug-x`, `config-release`, `config-docker`, `run-debug`, `run-watch`, `www-rebuild`; `l-run-ui-tests.sh` |
| `_run-common.sh` | Shared start-up logic for the local run scripts | sourced by `l-run-*.sh` |
| `_saml-setup.sh` | Switches an environment to SAML sign-in for a given Entra tenant | `make run-debug auth=saml`, `make run-watch auth=saml` |
| `_passkey-setup.sh` | Switches an environment back to passkey sign-in | `make run-debug auth=passkey`, `make run-watch auth=passkey` |
| `_swap-auth-storage.sh` | Swaps the stored passkey data when the sign-in mode changes | `_saml-setup.sh`, `_passkey-setup.sh` |
| `l-run-debug.sh` | Runs the already-built debug binary in a local environment and starts the dashboard development server (`make run-debug` builds first) | `make run-debug` |
| `l-run-watch.sh` | Runs under `cargo watch`, rebuilding and restarting on Rust changes | `make run-watch` |
| `l-run-release.sh` | Runs the release binary locally | `make run-release` |
| `l-run-ui-tests.sh` | Prepares `envs/local-tests`, starts Agent Stream in test mode, runs the Playwright suite in `ui-tests/`, stops Agent Stream | `make ui-test` |

## Docker

| Script | What it does | Called by |
| --- | --- | --- |
| `d-build.sh` | Builds the `agent-stream` image from `Dockerfile` or `Dockerfile.dev` | `make docker-build-local`, `docker-build-local-dev` |
| `d-run.sh` | Runs the image with `envs/docker` mounted | `make docker-run`, `docker-run-dev` |
| `d-shell.sh` | Starts a throwaway container from `agent-stream:local` with a bash entrypoint and opens a shell in it; the container is removed on exit | `make docker-shell` |

## Certificates

| Script | What it does | Called by |
| --- | --- | --- |
| `certs/generate-cert.sh` | Generates a self-signed TLS certificate | `make generate-cert`; `_certs.sh` |
| `certs/trust-cert.sh` | Adds a certificate to the system trust store | `make trust-cert` |
| `certs/generate-mtls-test-certs.sh` | Generates a CA and client certificates for exercising mTLS source authentication | run directly |

## DIDComm mediator

| Script | What it does | Called by |
| --- | --- | --- |
| `mediator/mediator-start.sh` | Sets up and starts a local DIDComm mediator in `envs/mediator` | `make mediator-up` (`make mediator`) |
| `mediator/mediator-stop.sh` | Stops the local mediator | `make mediator-down` |
| `mediator/mediator-provision.sh` | Provisions the mediator config on first run and starts its containers | `mediator-start.sh` |
| `mediator/reconcile-mediator-config.sh` | Rewrites `mediator.toml` for the mediator URL and admin DID | `mediator-provision.sh` |
| `mediator/test-reconcile-mediator-config.sh` | Self-test for `reconcile-mediator-config.sh` | run directly |
| `mediator/_url.sh` | URL and domain helpers | sourced by the mediator scripts |

## Checks and storage

| Script | What it does | Called by |
| --- | --- | --- |
| `bdd-gherkin.py` | Inventories and lints the BDD feature files and step bindings | `make lint-bdd-gherkin` |
| `setup-dynamodb.sh` | Creates the DynamoDB configuration table and loads the example configuration | `make setup-dynamodb` |
| `check-toolchain-sync.sh` | Fails when a workflow `toolchain:` pin differs from `rust-version` in `Cargo.toml` | the `release-guards` workflow; run directly |
| `checks.sh` | Runs `cargo fmt`, `cargo check`, Clippy (with fixes), build and tests in one go (Rust only) | run directly; `make ci` and `make lint` are the usual entry points |
| `local/parallel.sh` | Runs groups of make targets side by side, each logged to `tmp/local/<date>_<time>/<group>.log`, then prints a summary and fails if any group failed (`PARALLEL=0`: one at a time) | `make local` |
| `githooks/npm-audit`, `githooks/npm-lint` | Frontend audit and lint hook scripts | run directly; `make install-git-hooks` installs the pre-commit hooks |
