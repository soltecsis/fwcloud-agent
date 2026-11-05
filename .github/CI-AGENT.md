# FWCloud Agent CI delivery record

This record follows the nine deliveries in the Agent ENS CI epic. Each phase
requires its own issue or PR and review. Local implementation and verification
are recorded separately from GitHub execution, acceptance and promotion.
Automation alone does not establish ENS compliance.

## Delivery status

All PR, implementation commit, Actions run, artifact review and acceptance fields
remain pending until actual references are recorded. The source baseline for
phase 1 is `415d4c7` on `ENS`; the working branch is
`235-bring-fwcloud-agent-ci-to-the-ens-standard-and-gate-package-publication`.

| Phase | Scope | Status | Issue / PR | Implementation commit | Actions run / artifacts | Review date / reviewer | Decisions |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Reproducible CI foundation | Implemented locally; GitHub validation and acceptance pending; audit blocks | Pending | Pending | Pending GitHub execution | Pending / pending | Pins, locked Cargo operations, explicit triggers and foundation aggregate below |
| 2 | ShellCheck for maintained plugins | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Scope and justified exclusions pending review |
| 3 | Validated Rust test reports and reference coverage | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Preserve the existing 20% threshold until reviewed |
| 4 | Uncovered routes and security tests | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Deterministic tests without destructive system operations |
| 5 | Gitleaks and initial history audit | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Incremental scope and sanitized evidence pending implementation |
| 6 | Trivy / CycloneDX SBOM | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Keep Cargo audit; HIGH/CRITICAL policy includes unfixed findings |
| 7 | SonarQube Cloud / Quality Gate | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Rust analysis, Clippy import, coverage provenance and fork/Dependabot policy pending |
| 8 | Package integrity and publication gates | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Full security gate, source provenance and package integrity checks pending |
| 9 | Branch protection, evidence review and promotion | Pending separate delivery | Pending | Pending | Pending | Pending / pending | Require final `agent-ci` on ENS/main, verify update policy, promote and align devel |

## Phase 1 behavior

`.github/workflows/main.yml` runs on pushes to `ENS`, `main` and `devel`, PRs
targeting `ENS` and `main`, and manual dispatch. Existing `devel` push validation
is retained; additional integration branches require an explicit policy update.
Only a push to `main` in `soltecsis/fwcloud-agent` can reach external publication.
PRs and dispatches can build packages but cannot publish them.

Every checkout selects the PR head SHA or the event SHA, disables persisted Git
credentials, and verifies `git HEAD` against `SOURCE_COMMIT` during setup. PRs
validate their source revision rather than GitHub's synthetic merge commit.
Branch protection must require the source branch to be up to date with its base;
the actual GitHub setting has not been configured or verified here.

Workflow permissions are `contents: read`; validation needs no repository
secrets. New revisions cancel older executions of the same PR. Pushes and manual
executions are serialized by event/ref and do not cancel an active publication.
All jobs have explicit timeouts. Hosted runners use `ubuntu-24.04`; their image
and APT build prerequisites remain mutable, so this is reproducible Rust input
selection, not a claim of byte-identical package reproducibility.

| Job | Required behavior |
| --- | --- |
| `quality` | CI helper tests, `cargo check --locked --all-targets`, Rustfmt and Clippy with warnings denied |
| `security_audit` | Pinned `cargo audit --file Cargo.lock`; findings and execution errors fail the job |
| `test` | `cargo test --locked` |
| `coverage` | Pinned Tarpaulin, locked resolution, XML report, existing `--ignore-tests --fail-under 20` |
| `build` | `cargo build --locked`, after the preceding jobs succeed |
| `agent-ci` | Always evaluates the exact required job set and accepts only `success` |
| `deb-package`, `rpm-package` | Run after `agent-ci`; use the same source SHA and locked MUSL builds |
| Four external publishers | Run only on a `main` push after `agent-ci` and both package jobs succeed |

The current `agent-ci` is a **foundation aggregate**. It does not yet cover
ShellCheck, Gitleaks, Trivy/SBOM or SonarQube. No placeholder jobs report those
controls as successful. Phases 2, 5, 6 and 7 must extend its dependencies and
failure checks before the epic's complete mandatory gate can be accepted.
Existing publishers remain operational behind the foundation checks; the final
security publication guarantee is pending phases 5–8. Do not promote this phase
alone as the completed epic.

Clippy retains its previous default target scope. A local trial with
`--all-targets` also linted existing test code and failed on pre-existing issues,
including a discarded future handle and comparison of `sort()` return values.
Expanding that lint scope and repairing those tests needs its own reviewed
change; no lint allowances were added to hide the findings.

## Pinned inputs and packaging

`rust-toolchain.toml` selects Rust `1.99.1` with Rustfmt and Clippy. The shared
`.github/actions/setup-rust` action installs that release without changing the
global default, checks the actual Rust/Cargo releases, and verifies the compiler
commit in both components' version output. Rustup verifies downloaded component
checksums. All external actions use full commit SHAs.

`.github/ci-tools.toml` pins `cargo-audit 0.22.2`, `cargo-tarpaulin 0.37.5`,
`cargo-deb 3.8.0` and `cargo-rpm 0.8.0`. Tools are installed from `crates-io` with
exact versions and their published lockfiles, then their CLI versions are
checked. Dependency updates must deliberately update and review the lockfiles or
tool pins; CI does not run `cargo update`.

The existing `.cargo/audit.toml` exception for `RUSTSEC-2026-0258` is retained.
Its justification, owner and expiry require review in phase 6. Retaining it does
not constitute a new acceptance decision. The advisory database remains current
at execution time rather than pinned to stale vulnerability intelligence.

DEB uses an explicit output directory, avoiding cargo-deb's changed default
location. RPM builds the binary with `cargo build --locked --release`, then
uses `cargo rpm build --no-cargo-build`. An absolute `CARGO_TARGET_DIR` avoids
cargo-rpm's internal unlocked metadata lookup. Package layout, scripts,
destinations and distribution lists are retained.

`cargo-rpm 0.8.0` is archived. Its locked installation succeeds with Rust 1.99.1
but warns about yanked `arc-swap 0.4.7` and future incompatibility in
`abscissa_core 0.5.2`. Replacing this packaging utility requires a separate
review of package behavior; these warnings are not silently removed by an
unlocked installation.

The retained, SHA-pinned Packagecloud action installs the Ruby `package_cloud`
gem without a version internally. That publication dependency is not made
reproducible by pinning the action alone. Replacing or pinning its publication
implementation remains an explicit phase 8 requirement.

## Evidence and retention

The shared setup action uploads `agent-environment-<job>-<run>-<attempt>` with
allowlisted JSON: verified source commit, repository, workflow, event/ref, run
ID, attempt, job, UTC recording time, runner image, `Cargo.lock` SHA-256, selected
pins and actual tool versions. These describe the setup environment and do not
claim that later job steps passed. Credentials and arbitrary environment values
are not collected. Setup, version verification or upload failures fail the job.

Environment artifacts and coverage XML request **90 days** retention. Coverage
upload is attempted after failures and requires a file to exist, but validated
test/coverage schemas and Sonar-compatible reports are phase 3 work. Packages
request **14 days** and fail upload when the package glob is empty. Publishers
download only the named package artifact from their run and attempt. A partial
rerun cannot consume an earlier attempt's package implicitly; rerun the package
producer jobs too when necessary.

Actual retention limits, expiration, artifact access restrictions and repository
visibility must be verified in GitHub during phase 9. Actions logs retain the
check output according to repository/organization policy, which is also pending
verification. Package provenance manifests, digest checks and reviewed security
reports remain phase 8 requirements.

## Verification record

Local verification uses the tracked source exported to
`/tmp/fwcloud-agent-ci-source` and an isolated Rust/Cargo installation in `/tmp`.
The developer's default Rust 1.73.0 and untracked application files are excluded.
No package installation, firewall modification or external publication is part
of this verification.

| Check | Local result |
| --- | --- |
| Rust 1.99.1 and component verification | Passed with the official release |
| CI helper and aggregate regression tests | 15 passed |
| `cargo check --locked --all-targets` | Passed |
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked -- -D warnings` | Passed with the existing default target scope |
| `cargo test --locked -j 2` with debug symbols disabled | Passed: 93 tests, zero failures or ignored tests |
| `cargo build --locked -j 2` with debug symbols disabled | Passed |
| Cargo audit 0.22.2 | Executed; failed with 13 vulnerabilities and 12 allowed warnings; blocks `agent-ci` and publication |
| Locked cargo-rpm 0.8.0 / cargo-deb 3.8.0 installation and version checks | Passed; RPM warnings documented above |
| Locked cargo-audit 0.22.2 / cargo-tarpaulin 0.37.5 installation and version checks | Passed |
| Tarpaulin / Rust 1.99.1 smoke fixture | Passed: one test, valid nonempty XML, 42.86% coverage passes 20%; threshold 100% correctly fails |
| Full Agent coverage and review of the 20% threshold | Pending GitHub execution and phase 3 review |
| Actionlint 1.7.7 | Passed |
| Aggregate failure/skip/cancel/missing-job cases | Passed, including each mandatory job and unexpected jobs |
| DEB/RPM creation, PR/push executions and publication blocking in GitHub | Pending |
| Branch protection / promotion / devel alignment | Pending |

The initial local test build and Tarpaulin installation exhausted the 7.5 GiB
temporary filesystem. After removing only generated build outputs, the tool
installation succeeded. The Rust test retry uses
`CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0` and `-j 2` to bound local
resource use. This does not establish a result for the workflow's normal debug
profile. Tests require disposable localhost listeners; the sandbox blocks
binding and ptrace, so those executions require the approved external context.

Audit observation: the unchanged source `Cargo.lock` SHA-256 was
`eaae4155c6e99f7466d1e153548c070fe7605192c79233cf8a6dcd0c2a60b438`.
The RustSec database revision was
`26fd2d43f7280a1fb925a3743ec463017afe7119` (1,409 advisories). The 13 blocking
findings affect `quinn-proto`, `rustls`, `rustls-webpki`, `webpki-root-certs`,
`zstd`, `zstd-safe` and `zstd-sys`. This result needs dependency remediation and
revalidation in its own delivery; the existing exception was not changed.

Before accepting phase 1, link its issue/PR, implementation commit and Actions
run, review the artifacts, and record the review date and responsible reviewer
in the delivery table. Later phases must update that table in their own PRs.

## References

- API policy reference: `fwcloud-api` branch `ENS`, `.github/CI-BACKEND.md` and
  `.github/workflows/nodejs.yml`; Agent-specific reporting and scanners remain
  separate implementations.
- [Rust release announcements](https://blog.rust-lang.org/releases/)
- [Rustup toolchain files](https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file)
- [Cargo audit](https://docs.rs/crate/cargo-audit/0.22.2)
- [Tarpaulin](https://docs.rs/crate/cargo-tarpaulin/0.37.5)
- [cargo-deb 3.8.0](https://docs.rs/crate/cargo-deb/3.8.0)
- [cargo-rpm target lookup](https://github.com/iqlusioninc/cargo-rpm/blob/321e182cd9d72cf5666663890493f0ea9cdcbdea/src/target.rs)
