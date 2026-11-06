# Progressive CI implementation for FWCloud Agent

## 1. Purpose and scope

This record follows the structure of FWCloud API's
[`.github/CI-BACKEND.md`](https://github.com/soltecsis/fwcloud-api/blob/d4627b256905853bd04eaa0432ba8466dae83545/.github/CI-BACKEND.md),
especially its Phase 1 section. It records the Agent ENS CI decisions, changes,
local validation and outstanding GitHub acceptance separately. Automation alone
does not establish ENS compliance.

| Field | Value |
| --- | --- |
| Repository | `soltecsis/fwcloud-agent` |
| Working branch | `236-chore-establish-a-reproducible-ci-foundation-for-fwcloud-agent` |
| Integration target | `ENS` |
| Implementation baseline | `c8fbe38`, existing `ENS` tip |
| Execution environment | GitHub Actions, `ubuntu-24.04` hosted runners |
| Evidence retention | 90 days requested for environment metadata and coverage; 14 days for packages |
| Last updated | 2026-11-05 |

### Baseline verification

Before this delivery, the remote
[`devel...ENS` comparison](https://github.com/soltecsis/fwcloud-agent/compare/devel...ENS)
reported `ahead_by: 3`, `behind_by: 0`, with merge base and `devel` tip
`415d4c7c05775718372e321c1b2652020d6646d6`. The existing `ENS` tip is
`c8fbe38`, which already includes the initial CI foundation and a dependency
security update through PR #245. Thus ENS contains the complete intended devel
baseline but is no longer identical to it. Local refs confirmed `0 3` for
`git rev-list --left-right --count origin/devel...origin/ENS`.

This delivery preserves ENS and builds on that history. No branch was recreated,
reset or force-pushed. The current working branch starts from the ENS tip.

## 2. Current technical decisions

- Validate PRs targeting `main`, `devel` and `ENS`, pushes to the same
  branches, and manual dispatch.
- Pin Rust and Cargo utilities to exact releases. Install the toolchain using
  the runner's Rustup; retain no archived `actions-rs/*` actions.
- Build and test using committed `Cargo.lock`. Reject dependency changes
  requiring regeneration until the updated lockfile is committed.
- Separate quality and tests. Use `agent-ci` as the stable Phase 1 status
  requiring both; retain audit and coverage as additional package prerequisites.
- Keep existing package layouts, destinations, distribution lists and
  main-push-only external publication restrictions. Full publication policy
  remains Phase 8 work.
- Keep each delivery reviewable and record local results separately from
  deployed Actions results. Future controls are not represented by placeholder
  jobs reporting success.

## 3. Delivery plan

| Phase | Scope | Status | Closure requirement |
| --- | --- | --- | --- |
| 1 | Reproducible CI foundation | Implemented locally; GitHub acceptance pending | Positive and negative PR checks, event/concurrency verification and reviewed evidence |
| 2 | ShellCheck for maintained plugins | Pending | Reviewed scope and justified exclusions; required shell checks |
| 3 | Test reports and reference coverage | Pending | Valid reports tied to run/revision; reviewed reference coverage and threshold |
| 4 | Uncovered routes and security tests | Pending | Deterministic route and security tests without destructive system operations |
| 5 | Gitleaks and initial history audit | Pending | Incremental/history scope verified; redacted reports and reviewed exceptions |
| 6 | Trivy and CycloneDX SBOM | Pending | Dependency inventory, HIGH/CRITICAL policy and reviewed audit exceptions |
| 7 | SonarQube Cloud and Quality Gate | Pending | Rust analysis, Clippy/coverage import, required gate and fork/Dependabot policy |
| 8 | Conditional package publication | Pending | Complete security gate, source/artifact provenance and package integrity verification |
| 9 | Branch protection, evidence review and promotion | Pending | Required final `agent-ci`, reviewed evidence, promotion and devel alignment |

PR, implementation commit, Actions run, artifact review, reviewer and acceptance
references for this delivery remain pending. The earlier foundation is recorded
in PR #245; it does not prove acceptance of these changes.

## 4. Phase 1 — Reproducible CI foundation

### 4.1. Files and changes

- `workflows/main.yml`: complete branch events, quality/test separation,
  analyzed SHA, aggregate and explicit package dependencies.
- `../rust-toolchain.toml`: retain the exact validated Rust release,
  `minimal` profile, Rustfmt and Clippy.
- `actions/setup-rust/action.yml`: shared Rustup setup, locked dependency
  preflight, Cargo cache and environment evidence.
- `ci-tools.toml`, `scripts/rust-ci.py`: exact utility releases and
  version/source verification; use `ANALYSIS_COMMIT` consistently.
- `scripts/test_rust_ci.py`, `scripts/test_workflow.py`: environment,
  aggregate failure cases and package/publication gate regressions.
- `../src/utils/files_list.rs`,
  `../src/workers/openvpn_status_collector.rs`,
  `../tests/common/mod.rs`: repair warnings exposed by all-target Clippy
  in test code.

The obsolete `checks` and separate debug `build` jobs are absent.
`cargo check`, unused version outputs, `cargo pkgid` and deprecated
`::set-output` are unnecessary. Application build now runs in `test`.
No application dependency or lockfile changes are part of this delivery.

### 4.2. Toolchain and lockfile policy

On 2026-11-05 the
[official stable manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml)
reported Rust `1.99.1` (manifest date 2026-10-15, compiler commit
`58cf8f9c35b355199727627d07ae34a4e2846d67`). The repository already pins
that release; local validation confirms retaining it.

`rust-toolchain.toml` selects the `minimal` profile and the
`rustfmt` and `clippy` components. The shared action runs
`rustup toolchain install` with the configured release and
`--no-self-update`, then exports `RUSTUP_TOOLCHAIN`. It does not
change the developer's global default. Setup verifies and prints the actual
Rust/Cargo releases (`rustc 1.99.1`, `cargo 1.99.1`) and component
compiler provenance.

Required quality and test commands are:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo build --locked
cargo test --locked
```

The shared setup first validates
`cargo metadata --all-features --locked --format-version 1`. This rejects
a stale lockfile before the cache action, whose own metadata lookups could
otherwise resolve dependencies. Every job using Cargo also finishes with
`git diff --exit-code -- Cargo.lock` under `always()`, including on
failure. CI never runs `cargo update`.

Cargo utilities remain pinned in `ci-tools.toml`:

| Utility | Exact release |
| --- | --- |
| `cargo-audit` | `0.22.2` |
| `cargo-tarpaulin` | `0.37.5` |
| `cargo-deb` | `3.8.0` |
| `cargo-rpm` | `0.8.0` |

Installation uses `cargo install --locked --version =<release> --registry
crates-io`, followed by CLI version verification. Update pins and lockfiles
deliberately and validate them together.

### 4.3. Cargo caching and Action pins

The shared setup uses
[`Swatinem/rust-cache v2.9.3`](https://github.com/Swatinem/rust-cache/tree/d1527c8f67ef9af357290475d4af4b0fab8f12e0),
pinned to commit `d1527c8f67ef9af357290475d4af4b0fab8f12e0`.

The explicit cache key hashes `Cargo.lock` and `rust-toolchain.toml`.
The prefix also hashes the toolchain file, keeping fallback restores within that
exact toolchain configuration. The action additionally keys by compiler
release/host/hash, job, Cargo manifests and build environment. Cargo binaries
are excluded with `cache-bin: false`.

Only the cache step uses `continue-on-error: true`. No build, test, lint,
setup or lockfile check is conditional on a cache hit or marked optional.
A cache error therefore causes a normal compilation instead of bypassing checks.
Live restore/save and failure behavior still require GitHub execution.

Other external actions used by Phase 1, including nested setup steps:

| Action | Version | Immutable commit |
| --- | --- | --- |
| `actions/checkout` | `v4.3.1` | `34e114876b0b11c390a56381ad16ebd13914f8d5` |
| `actions/upload-artifact` | `v4.6.2` | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

All other retained external actions also use full commit SHAs. The local
`./.github/actions/setup-rust` composite is loaded from the exact checked-out
analysis revision.

### 4.4. Jobs and package gates

| Job | Responsibility | Timeout |
| --- | --- | --- |
| `quality` / `FWCloud-Agent Quality` | Setup/cache, helper tests, Rustfmt, Clippy across all targets with warnings denied | 20 minutes |
| `test` / `FWCloud-Agent Test` | Setup/cache, locked application build and automated tests | 30 minutes |
| `agent-ci` | Always evaluate `quality` and `test`; require exactly both results to be `success` | 5 minutes |
| `security_audit` | Pinned `cargo audit --file Cargo.lock` | 30 minutes |
| `coverage` | Locked Tarpaulin, XML evidence, existing `--ignore-tests --fail-under 20` | 45 minutes |
| `deb-package`, `rpm-package` | Require `agent-ci`, `security_audit` and `coverage`; build locked MUSL packages | 45 minutes |
| Four external publishers | Require `agent-ci` and both package jobs; publish only a `main` push in the upstream repository | 15 minutes |

A required job failure, skip, cancellation, missing result or unexpected job set
fails `agent-ci`. Cancelling the entire workflow can also cancel the aggregate;
that execution cannot satisfy a required successful status. Audit and coverage
are separate mandatory packaging dependencies during this transition. Later
phases must extend both the aggregate's dependency list and its result checks.

All-target Clippy includes unit and integration test code. Findings were fixed
without lint suppressions: detach the spawned server explicitly, remove redundant
borrows/options, iterate over values, assert the actual directory error and
compare sorted file lists instead of the unit values returned by `sort()`.

DEB retains an explicit output directory. RPM builds the binary with
`cargo build --locked --release`, then invokes
`cargo rpm build --no-cargo-build`. Its absolute `CARGO_TARGET_DIR`
avoids an internal unlocked metadata lookup. Layouts, scripts and distribution
destinations remain unchanged.

The existing `.cargo/audit.toml` exception for `RUSTSEC-2026-0258`
remains; review its justification, owner and expiry in Phase 6. Cargo audit remains
active against the current advisory database.

The archived `cargo-rpm 0.8.0` utility is distinct from the removed
`actions-rs/*` actions. Its existing yanked/future-incompatibility dependency
warnings require a separately reviewed packaging replacement. The pinned
Packagecloud action also installs an unversioned Ruby `package_cloud` gem
internally; that publication dependency remains Phase 8 work.

### 4.5. Events, permissions and concurrency

| Event | Configuration |
| --- | --- |
| `push` | `main`, `devel`, `ENS` |
| `pull_request` | Targets `main`, `devel`, `ENS` |
| `workflow_dispatch` | Manual execution when the workflow is available for dispatch in GitHub |

Workflow permissions are `contents: read`; no validation job requires extra
permissions or distribution secrets. Secrets remain confined to the existing
external publisher jobs.

Hosted runner images and APT prerequisites remain mutable. The toolchain,
dependency resolution and Action references are pinned; byte-identical package
reproducibility is not claimed by this phase.

`CARGO_TERM_COLOR=always` enables readable Cargo output.
`ANALYSIS_COMMIT` is the PR head SHA or event SHA. Every source checkout
uses it, disables persisted credentials, and verifies actual Git HEAD against
it before recording evidence. PR validation analyzes the source revision;
branch protection must separately require that revision to be up to date with
its base.

The concurrency group includes workflow, event and PR number or ref.
`cancel-in-progress` is true only for PRs, so a new revision cancels the
obsolete run for that PR. Different PRs, branches and event types have separate
groups. Push/manual runs do not cancel active runs in their group.

### 4.6. Evidence and retention

The setup action uploads `agent-environment-<job>-<run>-<attempt>` with
allowlisted JSON: verified source commit, repository, event/ref, workflow, run,
attempt, job, UTC time, runner image, lockfile SHA-256, pins and actual versions.
These identify the setup environment; they do not claim later checks succeeded.
Credentials and arbitrary environment variables are not collected.

Environment and coverage artifacts request 90-day retention. Coverage upload is
attempted after failures and requires a report to exist. Validated test report
schemas and reference coverage are Phase 3 work. Package artifacts request
14 days. Publishers download only their named package artifact from the same
run and attempt; partial reruns must include package producers when needed.

Actual retention limits, visibility, log retention and artifact access remain
subject to repository/organization settings and Phase 9 review.

### 4.7. Local validation on 2026-11-05

Validation exports the tracked baseline plus these edits to
`/tmp/fwcloud-agent-phase1-source`, excluding unrelated untracked application
files. Rust/Cargo use isolated installations under `/tmp`; the developer's
default toolchain is unchanged. Local build/test use two compilation workers and
disable debug symbols to limit temporary disk consumption. Workflow commands
retain normal runner defaults.

| Check | Result |
| --- | --- |
| Remote ENS/devel baseline | ENS contains devel, three commits ahead, none behind; branch preserved |
| Official stable selection | Rust/Cargo `1.99.1`; minimal profile with Rustfmt and Clippy |
| Rustfmt | Passed |
| `cargo clippy --all-targets --locked -- -D warnings` | Passed with test-code findings repaired |
| `cargo build --locked` | Passed |
| `cargo test --locked` | 93 passed, zero failures or ignored tests |
| Stale-lockfile negative probes | Metadata, build, test and Clippy rejected an added dependency requiring lock regeneration; original lock bytes preserved |
| Warning injected into `tests/` | All-target Clippy failed with `let_underscore_future`; temporary probe removed |
| CI helper and workflow regression suite | 19 passed, including aggregate failure/skip/cancel/missing-result cases and packaging/publication gates |
| Current Cargo audit `0.22.2` | Passed against 1,409 advisories and 330 locked dependencies, retaining the existing exception |
| Full Tarpaulin `0.37.5` coverage | Passed: 60.90% (721/1,184 lines), above the unchanged 20% threshold; nonempty XML generated |
| Locked metadata preflight | Passed after downloading missing target-specific crates |
| Workflow/composite YAML policy review | Passed: all events, permissions, concurrency, analyzed SHA, immutable action pins, isolated cache prefix, mandatory commands and final lockfile guards |
| Actionlint `1.7.7` | Passed |
| `Cargo.lock` | Unchanged |
| GitHub event, cache, cancellation and branch-protection behavior | Pending live verification |
| DEB/RPM generation and external publication | Not executed locally |

The sandbox initially blocked HTTP test listeners and dependency/advisory
downloads. The affected checks were rerun with the necessary execution
permissions. Coverage also requires a writable build directory and tracing
permissions. These local environment constraints are not waived CI checks.

The local coverage report is
`/tmp/fwcloud-agent-phase1-source/reports/coverage/cobertura.xml`.
Its XML parses successfully. This is local evidence; the hosted runner result
and the Phase 3 reference coverage review remain pending.

### 4.8. Acceptance and remaining work

- [x] Configure push and PR events for all three branches and manual dispatch.
- [x] Use an exact Rust release, minimal profile, Rustfmt and Clippy.
- [x] Remove archived Rust Actions, obsolete checks and redundant build job.
- [x] Pin external actions, configure Cargo caching and enforce the lockfile.
- [x] Run quality separately from locked build/tests and reject test-code warnings.
- [x] Verify aggregate rejection of failed, skipped, cancelled or missing jobs.
- [x] Retain audit, the 20% coverage requirement and both packaging gates.
- [x] Document the implementation and full pending roadmap.
- [ ] Record PR/implementation commit and successful Actions run/artifact references.
- [ ] Exercise PRs to ENS/main/devel, pushes and manual dispatch in GitHub.
- [ ] Verify obsolete PR runs cancel while unrelated PR/branch groups remain independent.
- [ ] Verify cold/warm caches and a cache outage do not bypass required commands.
- [ ] Review coverage XML, DEB/RPM generation and publication blocking in Actions.
- [ ] Configure and verify branch protection requiring successful `agent-ci`.
- [ ] Complete subsequent phases before accepting the full security/publication gate.

## 5. Updating this record

Update this document with each delivery. Record the exact revision, commands,
environment, results, limitations, PR/run/artifact links and reviewer. Keep
implemented behavior separate from planned controls and GitHub acceptance.
Retest affected checks after changes and do not reuse results from an earlier
revision without establishing their applicability.
