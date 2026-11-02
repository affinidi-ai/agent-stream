# Contributing

Affinidi Agent Stream is a single Rust binary (`agent-stream`) with a dashboard under
`www/default/`. To propose a change, first discuss it by creating a new
[GitHub issue](https://github.com/affinidi-ai/agent-stream/issues/new).

## Development Requirements

- Rust `1.95.0` or newer, 2024 Edition (the minimum is declared in [`Cargo.toml`](Cargo.toml))
- Node.js 22 or newer with npm (to build and run the dashboard under `www/default/`)
- [`cargo-audit`](https://crates.io/crates/cargo-audit) and [`cargo-deny`](https://crates.io/crates/cargo-deny)
  for `make audit` and `make license-check` (`make install-deps` installs them on macOS)

Runtime state uses an in-memory DashMap cache backed by filesystem JSON storage; there is no
external database dependency. For source setup and the day-to-day run targets, see
[`docs/development/GETTING_STARTED.md`](docs/development/GETTING_STARTED.md) and
[`docs/development/DEVELOPMENT.md`](docs/development/DEVELOPMENT.md).

To find your way around the code, start with [`ARCHITECTURE.md`](ARCHITECTURE.md). For the
recurring change shapes, such as adding a provider, a pipeline stage, or a management
endpoint, see [`docs/development/MAKING_CHANGES.md`](docs/development/MAKING_CHANGES.md).

## Changelog Fragments

**Every change requires a changelog fragment; never edit [`CHANGELOG.md`](CHANGELOG.md)
directly** (it is generated at release). Create or append to `.changelog/wip/<branch>.yaml`,
where the filename is the current branch with every `/` replaced by `_` (read `.git/HEAD` for
the branch name). On `main`, create a new `.changelog/wip/main-<timestamp>.yaml` per session.
Each entry needs a `timestamp`, a `title` (an imperative sentence of 80 characters or less),
and a `description`. User-visible work goes under `added` / `changed` / `fixed` / `removed` /
`security` / `breaking`; tests, docs, CI, and refactors go under the public category that best
describes their user-visible effect. If a change has no public release effect, leave all category
lists empty. The `branch` field
is the branch name as it is, with its slashes. For example, on branch `feat/my-change`, the file
`.changelog/wip/feat_my-change.yaml` reads:

```yaml
branch: feat/my-change
changes:
  added:
    - timestamp: '2026-10-19T12:00:00.000Z'
      title: Add weighted load balancing across LLM providers
      description: Distribute requests across the configured providers by weight.
  changed: []
  fixed: []
  removed: []
  security: []
  breaking: []
```

Append further entries to the same file for later changes on the branch. Check your fragments
with `python3 .github/scripts/check_changelog_fragments.py` (needs PyYAML); CI runs the same
validation and requires every pull request to add or change its branch fragment. See
[`docs/development/RELEASING.md`](docs/development/RELEASING.md) for how fragments become a
release.

## Code Quality Expectations

1. Make the smallest correct change and leave the code better than you found it: DRY, no dead
   code, single-responsibility functions.
2. Cover changes with tests, positive and negative cases, and assert returned values rather
   than just the absence of errors.
   [`docs/development/TESTING.md`](docs/development/TESTING.md) sets out the test layers and
   which one a given change belongs in.
3. Avoid comments unless a linter requires them or the intent is genuinely non-obvious; code
   should be self-explanatory. Never leave implementation-history breadcrumbs (plan numbers,
   phases, requirement labels).
4. Use clear, unambiguous names; avoid single letters like `i` or abbreviations.
5. Keep docs in sync with code in the same change (see [`docs/README.md`](docs/README.md)).

## Before Opening A Pull Request

Run the check-only targets before you open a pull request:

| Command | What it runs |
| --- | --- |
| `make fmt-check` | Check Rust and frontend formatting without modifying files (a frontend formatting failure is reported but does not fail the target) |
| `make clippy-ci` | Run Clippy without fixes, failing on warnings |
| `make npm-lint-ci` | Run frontend ESLint without fixes |
| `make test` | Run every Rust test target, including the BDD scenarios |
| `make license-check` | Check dependency licences against `deny.toml` |
| `make audit` | Run the dependency security audit |
| `make lint-bdd-gherkin` | Lint `.feature` files and step bindings, as CI does |

If you changed the dashboard, also run `make npm-test`. `make lint` is intended for development
and may apply Clippy and ESLint fixes; use the targets above for check-only runs. `make ci`
runs the broader local preflight.

For faster inner-loop feedback, run `make config-test` once, then use
`cargo test --no-run --bin agent-stream` for a compile check and `cargo test --bin agent-stream "<module path>"` to run a single module's tests.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members
- Avoiding obvious comments about things like code styling and indentation.
  **If you see yourself wanting to do that more than once - open an issue to
  update the formatting or lint rules to address this concern once and for all.
  Code reviews should be about logic, not indenting or adding more newlines.**

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting

### Scope

This Code of Conduct applies both within project spaces and in public spaces
when an individual is representing the project or its community. Examples of
representing a project or community include using an official project e-mail
address, posting via an official social media account, or acting as an appointed
representative at an online or offline event. Representation of a project may be
further defined and clarified by project maintainers.

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be
reported by contacting the project team through the
[Affinidi support form](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).
All complaints will be reviewed and investigated and will result in a response
that is deemed necessary and appropriate to the circumstances. The project team
is obligated to maintain confidentiality with regard to the reporter of an
incident. Further details of specific enforcement policies may be posted
separately.

Project maintainers who do not follow or enforce the Code of Conduct in good
faith may face temporary or permanent repercussions as determined by other
members of the project's leadership.

### Attribution

This Code of Conduct is adapted from the [Contributor Covenant](https://www.contributor-covenant.org),
version 1.4, available at
<https://www.contributor-covenant.org/version/1/4/code-of-conduct.html>.
