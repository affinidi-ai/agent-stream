# BDD Gherkin Tool

`scripts/bdd-gherkin.py` is the required inventory and lint tool for Agent Stream BDD/Gherkin work. It keeps `.feature` files, cucumber-rs step bindings, and cross-suite wording aligned.

The tool scans:

- `tests/features/**/*.feature` for scenarios
- `tests/*_bdd/steps/*.rs` for bindings in product-domain step modules
- `tests/*_bdd/**/*.rs` and `tests/bdd_support/**/*.rs` for internal helper references

Nested `steps/support/` modules are deliberately excluded from binding discovery and must not contain Cucumber attributes. Generated files are written under `.bdd-gherkin/`, which is ignored by git.

## Why this tool exists

Generic Gherkin linters such as `gherkin-lint` and `gherlint` cover useful feature-file style rules, but they do not understand this repo's cucumber-rs bindings or Agent Stream product vocabulary. This tool is intentionally repo-specific: it connects Gherkin steps to Rust `#[given]`, `#[when]`, and `#[then]` bindings, detects unmatched/ambiguous/unused bindings, accounts for internal helper references, compares suite wording, and generates the AI-readable DSL inventory used by the BDD skill.

The implementation is a single Python script using only the standard library. It has no npm/pip dependency graph, no package install step, no postinstall scripts, and no network access. That keeps CI and supply-chain surface small while preserving checks that external linters cannot provide.

AI makes small deterministic tools cheap to create, but the bar for keeping one is still practical value: the tool must be simple, self-tested, documented, CI-enforced, and easier to maintain than adopting a dependency that only solves part of the problem. Use external Gherkin linters as references for rule ideas; do not add one unless the built-in parser/rules become insufficient.

## Workflow

Before adding or renaming Gherkin language:

```bash
scripts/bdd-gherkin.py --inventory
```

Read `.bdd-gherkin/context.md` completely. It is the current DSL catalog: all step bindings, usage counts, internal helper reference counts, source file/line, and bound Rust function names. Before reusing a non-trivial step, read its Rust function; step wording is the DSL contract, but behavior lives in the binding implementation.

After changing `.feature` files or step bindings:

```bash
scripts/bdd-gherkin.py --lint
```

Treat errors as blocking. Warnings are review prompts and should be resolved or consciously accepted.

## Commands

| Command | Purpose |
| --- | --- |
| `scripts/bdd-gherkin.py` | Print help. |
| `scripts/bdd-gherkin.py --inventory [PATH]` | Write the AI-oriented step inventory context. Defaults to `.bdd-gherkin/context.md`. |
| `scripts/bdd-gherkin.py --lint` | Print errors/warnings and exit non-zero when hard errors exist. |
| `scripts/bdd-gherkin.py --lint --verbose` | Include informational diagnostics such as exact cross-suite overlaps and regex cleanup hints. |
| `scripts/bdd-gherkin.py --debug-json [PATH]` | Write raw parser/match data. Defaults to `.bdd-gherkin/debug.json`. |
| `scripts/bdd-gherkin.py --self-test` | Run built-in parser/tag accounting self-tests. Use after changing parser or lint rules. |
| `scripts/bdd-gherkin.py --root PATH ...` | Run against a repository root other than the current directory. |

## Lint severities

### Errors

Errors fail `--lint` and the CI gate.

| Check | Why it fails |
| --- | --- |
| Unmatched required feature step | Non-draft scenarios must be executable. |
| Unmatched `@known-bug` step | Known bugs are executable-but-skipped by default; they still need bindings. |
| Ambiguous feature step | One step must resolve to exactly one binding. |
| Unused step binding | Dead Cucumber bindings drift from the executable DSL. Delete it; if the Rust function is still used internally, remove only the Cucumber attribute. |
| Repeated `Given`/`Then` keyword | After the first `Given` or `Then`, use `And` for additional setup/assertion steps. |
| Missing `When` step | Every scenario should perform one explicit caller/operator action. |
| Multiple `When` steps | One scenario should perform one caller/operator action. Move setup to `Given` or split the scenario. |
| `Background` contains `When` or `Then` | `Background` may only seed prerequisite state. |
| Step keywords out of logical order | Scenario steps must progress from `Given` setup to `When` action to `Then` assertion. |
| `Examples` under plain `Scenario` | `Examples` belongs only under `Scenario Outline`. |
| Empty feature file / no scenarios | Feature files must contain at least one scenario. |
| Empty `Background` | A declared `Background` must contain setup steps. |
| Empty scenario | A scenario or scenario outline must contain its own steps. |
| Scenario Outline without examples | An outline with no examples is not an executable behavior matrix. |
| Scenario Outline placeholder missing from `Examples` | Every `<placeholder>` used by steps must have an examples column. |
| Scenario Outline has unused `Examples` columns | Every examples column must be part of the executable scenario wording. |

### Warnings

Warnings do not fail `--lint` by default, but they should be reviewed.

| Check | Review action |
| --- | --- |
| Unmatched `@wip` step | Allowed only for intentional draft/non-executable work. |
| Fully bound `@wip` scenario | Remove `@wip` unless it intentionally remains draft-only. |
| Unknown tag | Use documented runtime-significant tags or document why a new executable tag is needed. Known tags are `@wip`, `@known-bug`, and `@debug`. |
| Duplicate tags on one scenario | Remove repeated tags. |
| Duplicate scenario title within one feature | Rename scenarios so review and runner output stay unambiguous. |
| Suspicious terminology | Check glossary drift and rename unless the term is part of the behavior under test. |
| Harness mechanics wording | Replace harness-internal terms unless they are intentionally part of the behavior under test. |
| Broad regex step binding | Replace broad regex captures such as `.*` or `(.+)` with narrower regexes or Cucumber expressions. |
| Near-duplicate cross-suite binding | Review whether suites should share wording or intentionally differ. Bindings that already have an exact cross-suite wording match are excluded from this warning so canonical shared DSL does not create noisy secondary candidates. |

### Info

Informational diagnostics appear only with `--lint --verbose`.

| Check | Meaning |
| --- | --- |
| Exact cross-suite binding overlap | Usually good: suites already use the same normalized business wording. |
| Regex binding could be a Cucumber expression | Style cleanup opportunity for simple regex bindings that can be expressed as Cucumber expressions. |

## Tags

- `@wip`: draft/non-executable scenario. It may temporarily contain unbound steps and is skipped by the default runner.
- `@known-bug`: executable scenario documenting an accepted current defect. It is skipped by the default runner but must remain fully bound.
- `@debug`: temporary local focus tag used with `DEBUG=1`.

Avoid inert grouping tags. Prefer feature names, scenario titles, and directory structure for organization. Unknown tags are warnings so typo drift is visible without blocking exploratory naming.

## Debug data

Use debug JSON for parser investigations or tooling development:

```bash
scripts/bdd-gherkin.py --debug-json
```

The JSON includes bindings, expanded feature steps, parsed scenarios, binding matches, exact overlaps, near duplicates, usage counts, function reference counts, tagged scenarios, unmatched step groups, term warning categories, terminology warnings, and summary counters.

## CI

CI, and `make lint-bdd-gherkin` locally, runs:

```bash
python3 -m py_compile scripts/bdd-gherkin.py
scripts/bdd-gherkin.py --self-test
scripts/bdd-gherkin.py --lint
```

This keeps parser sanity checks and binding/feature drift validation in the normal lint stage.

## Term warning categories

Suspicious/domain-drift terms and harness-mechanics terms are tracked in one authoritative data file:

```text
docs/testing/bdd-gherkin-term-warnings.json
```

The file is intentionally human-readable so agents can load it as context when reviewing wording. Update it when adding, removing, or recategorising wording checks. The active categories and terms are also emitted in `--debug-json` as `term_warning_categories`.

## Maintenance

When changing parser or lint rules:

1. Update `scripts/bdd-gherkin.py --self-test` fixtures for the behavior.
2. Run `python3 -m py_compile scripts/bdd-gherkin.py`.
3. Run `scripts/bdd-gherkin.py --self-test`.
4. Run `scripts/bdd-gherkin.py --lint`.
5. Update `docs/testing/bdd-gherkin-term-warnings.json` for term warning changes.
6. Update this document and `docs/testing/bdd-gherkin.md` if workflow or severity changes.
