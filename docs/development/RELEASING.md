# Releasing

How Agent Stream versions, tags, and `CHANGELOG.md` relate, and what a contributor does so a
change is released correctly. Releases are prepared by GitHub Actions from the changelog
fragments and tagged; an ordinary pull request never bumps the version or edits `CHANGELOG.md`.

## Version source

The product version is the `version` in [`Cargo.toml`](../../Cargo.toml), kept in step with
[`Cargo.lock`](../../Cargo.lock). The dashboard's `www/default/package.json` carries its own
package version, which is not the product version and does not change on release.

## Tags

| Tag | Meaning | `Cargo.toml` |
| --- | --- | --- |
| `vX.Y.Z` | A release | Reads `X.Y.Z` at the tagged commit |
| Anything else, such as `vX.Y.Z-<name>.<n>` | A build of unreleased work for testing | Unchanged; the tag is not a version |

A release tags the current `Cargo.toml` version if that version has no tag yet. If it is
already tagged, the release first bumps `Cargo.toml` and `Cargo.lock` by the increment the
maintainer chose (patch, minor, or major) and tags the new version. Either way, a release tag
always matches the crate version on disk.

## Changelog fragments

Every change adds a fragment; [`CHANGELOG.md`](../../CHANGELOG.md) is generated from them at
release. Create or append to `.changelog/wip/<branch>.yaml`, where the filename is the branch
name with every `/` replaced by `_`. On `main`, create a new `.changelog/wip/main-<timestamp>.yaml`
for each session instead of appending to an existing one.

Each entry has a `timestamp`, a `title` (a changelog-ready imperative sentence of 80
characters or less, optionally starting with `⭐` for an important change), and a
`description` of what changed and why. File it under one of the public categories `added`,
`changed`, `fixed`, `removed`, `security` or `breaking`. Tests, docs, CI, and refactors go under
the category that best matches their user-visible effect; a change with no public release effect
leaves every category list empty.

The _Changelog fragments_ section of [`AGENTS.md`](../../AGENTS.md#changelog-fragments) has
the exact file format.

At release, the fragments are folded into a new `CHANGELOG.md` section for the version, in
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, and archived under
`.changelog/history/`. That section is also the release notes.

## Release workflow

1. A maintainer runs the **Prepare release** workflow
   ([`release.yml`](../../.github/workflows/release.yml)) on `main` and picks the increment.
   It validates the fragments, bumps the version, folds the fragments into `CHANGELOG.md`
   with [`.github/scripts/changelog.py`](../../.github/scripts/changelog.py), and opens a
   `release/vX.Y.Z` pull request. Only one release pull request can be open at a time.
2. Reviewers check the new `CHANGELOG.md` section and edit its wording in that pull request
   if needed.
3. Squash-merging it runs **Publish release**
   ([`publish-release.yml`](../../.github/workflows/publish-release.yml)). It builds the Linux
   x86_64 binary, attests its build provenance, tags the merge commit, and creates the GitHub
   Release with the binary, its SHA-256 checksum, and the changelog section.

Both workflows run in the `release` GitHub environment and commit, tag, and publish as a
GitHub App. The repository needs that environment with the `RELEASE_BOT_APP_ID` and
`RELEASE_BOT_PRIVATE_KEY` secrets, and the App needs contents and pull request write access.

## Before a release

A release commit passes the fast checks and the appliance testkit. Locally,
`make confidence-fast` runs the former and `make confidence-full` adds the latter; see
[`TESTING.md`](TESTING.md#local-confidence-suites).

## Related

- [`CONTRIBUTING.md`](../../CONTRIBUTING.md): what every contribution includes.
- [`TESTING.md`](TESTING.md): the checks that run before a pull request and a release.
