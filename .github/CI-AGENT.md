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
| Working branch | `239-test-cover-untested-system-management-routes-with-isolated-integration-tests` |
| Integration target | `ENS` |
| Phase 1 implementation baseline | `c8fbe38`, existing `ENS` tip at that delivery |
| Phase 2 script baseline | `2cdfefcef2a6cc887baa979971872de36e21ddf6` |
| Reporting implementation base | `127ebb9e589d5f4261320824f8cf153943cc2401` |
| Execution environment | GitHub Actions, `ubuntu-24.04` hosted runners |
| Evidence retention | 90 days requested for environment metadata, coverage and ShellCheck; 14 days for packages |
| Last updated | 2026-11-06 |

### Phase 1 baseline verification

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
- Separate quality and tests. `agent-ci` requires both, and `test` now includes
  reporting and the mandatory coverage gate. Packages also require dependency audit.
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
| 2 | ShellCheck for plugins and Debian maintenance scripts | Implemented locally; GitHub acceptance pending | Baseline reviewed without exclusions; exercise blocking shell checks in Actions |
| 3 | Test reports and reference coverage (API Phase 2) | Implemented and verified locally; hosted acceptance pending | Valid artifacts tied to run/revision; reviewed baseline and hosted performance comparison |
| 4 | Uncovered routes and security tests | Implemented and verified locally; hosted execution pending | Deterministic route and security tests without destructive system operations |
| 5 | Gitleaks and initial history audit | Pending | Incremental/history scope verified; redacted reports and reviewed exceptions |
| 6 | Trivy and CycloneDX SBOM | Pending | Dependency inventory, HIGH/CRITICAL policy and reviewed audit exceptions |
| 7 | SonarQube Cloud and Quality Gate | Pending | Rust analysis, Clippy/coverage import, required gate and fork/Dependabot policy |
| 8 | Conditional package publication | Pending | Complete security gate, source/artifact provenance and package integrity verification |
| 9 | Branch protection, evidence review and promotion | Pending | Required final `agent-ci`, reviewed evidence, promotion and devel alignment |

PR, implementation commit, Actions run, artifact review, reviewer and acceptance
references for this delivery remain pending. The earlier foundation is recorded
in PR #245; it does not prove acceptance of these changes.

## 4. Phase 1 — Reproducible CI foundation

This section retains the Phase 1 implementation and validation history. Section 6
supersedes its test/coverage commands, artifacts and package dependency layout.

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

The Phase 1 quality and test commands were (section 6 replaces the test commands):

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

Cargo utilities remain pinned in `ci-tools.toml` (Tarpaulin is retained only for
historical comparisons; the workflow no longer installs or runs it):

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
| `quality` / `FWCloud-Agent Quality` | Setup/cache, helper tests, Rustfmt, Clippy across all targets with warnings denied, verified ShellCheck installation and shell analysis | 20 minutes |
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

## 5. Phase 2 — ShellCheck

### 5.1. Installation and scope

`scripts/shellcheck-ci.py` installs the official Linux x86_64
[ShellCheck v0.11.0 release](https://github.com/koalaman/shellcheck/releases/tag/v0.11.0).
The exact archive is `shellcheck-v0.11.0.linux.x86_64.tar.xz`, downloaded from
`https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz`.
Its required SHA-256 is:

```text
8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
```

Installation checks the downloaded archive with Python's SHA-256 implementation
before extracting it under `RUNNER_TEMP/agent-shellcheck`. It executes the
extracted binary's `--version` and requires the exact line `version: 0.11.0`
before exporting `SHELLCHECK` through `GITHUB_ENV`. Download, checksum,
extraction, execution and version failures fail the step. No distribution
ShellCheck package is installed and no root privileges are required.

Analysis discovers `plugins/**/*.sh` recursively, including `plugins/lib.sh`
and newly added plugin files. It explicitly requires each of
`.deb/maintainer-scripts/preinst`, `postinst`, `prerm` and `postrm` despite
their lack of an extension. Missing plugin directories, an empty plugin scope,
unreadable directory traversal, invalid plugin inputs or any missing maintenance
script fail analysis. Paths are passed as individual process arguments, including
paths containing spaces.

The measured scope is **27 files**: 23 plugin scripts and four maintenance
scripts. Of these, 22 declare Bash and five declare POSIX `sh`: the four Debian
scripts plus `plugins/openvpn-2fa/check_2fa.sh`. No global shell override is used.
`--norc` and an empty `SHELLCHECK_OPTS` keep ambient configuration from changing
the interpreter or hiding findings. ShellCheck reads scripts as static input;
it does not execute or source them in a shell.

### 5.2. Measured initial baseline

On 2026-11-06, the checksum-verified binary analyzed the complete scope from
`2cdfefcef2a6cc887baa979971872de36e21ddf6`, before enabling the error gate.
No plugin or maintenance script was modified. The initial command used
`--norc --severity=style --format=json1` with all 27 paths and an empty
`SHELLCHECK_OPTS`.

| Severity | Findings |
| --- | --- |
| `error` | 0 |
| `warning` | 40 |
| `info` | 52 |
| `style` | 58 |
| Total | 150 |

| Rule | Severity | Count | Review and remediation direction |
| --- | --- | --- | --- |
| `SC2086` | `info` | 49 | Review unquoted expansion and unintended splitting/globbing, including package maintenance paths |
| `SC2006` | `style` | 35 | Replace legacy backticks with `$(...)` |
| `SC2166` | `warning` | 25 | Replace ambiguous test `-a`/`-o` expressions with separate conditions |
| `SC2181` | `style` | 20 | Prefer testing command status directly |
| `SC2164` | `warning` | 6 | Check failed directory changes before subsequent file operations |
| `SC2034` | `warning` | 5 | Distinguish library globals consumed by callers from unused assignments |
| `SC2003` | `style` | 3 | Review arithmetic using legacy `expr` |
| `SC2046` | `warning` | 2 | Quote command substitutions used in an OS test and an ntopng download URL |
| `SC2028` | `info` | 1 | Use `printf` for escape handling in the GeoIP message |
| `SC2103` | `info` | 1 | Review working-directory restoration in Web Safety |
| `SC2154` | `warning` | 1 | OpenVPN supplies `common_name` at runtime; verify the deployment contract |
| `SC2269` | `info` | 1 | Redundant `SERVER_CN` self-assignment in the OpenVPN 2FA helper |
| `SC2319` | `warning` | 1 | Web Safety error reporting reads the status of the intervening condition |

The review distinguishes these cases:

- Actionable defects: `plugins/websafety/websafety.sh:181` reports `$?` after
  `[ $? -ne 0 ]`, losing the certificate-generation command's status (`SC2319`).
  Six unchecked `cd` calls in Web Safety, DNS Safety and GeoIP (`SC2164`)
  can allow later operations to run in the wrong directory.
- Quoting and condition findings (`SC2046`, `SC2086`, `SC2166`) need
  case-by-case corrections. Assumptions about distribution strings, fixed
  directories or URLs do not constitute accepted exclusions.
- Context-dependent findings: `RELEASE` and `DIST_NUMBER` in `plugins/lib.sh`
  are consumed by plugins such as Zeek, although the library's standalone
  analysis reports them as unused (`SC2034`). `common_name` in
  `plugins/openvpn-2fa/check_2fa.sh:6` is expected from OpenVPN's environment
  (`SC2154`). This does not justify removing the other unused assignments in
  CrowdSec or DNS Safety without review.
- Style recommendations and the redundant `SERVER_CN` assignment remain
  visible remediation work. This integration changes no script behavior.

These are measured findings, not an allowlist. No existing finding was
suppressed or automatically approved.

### 5.3. Mandatory policy and evidence

The selected initial blocking severity is **`error`**, adopting the requested
policy after measuring zero errors and reviewing the 150 lower-severity
findings. This permits an immediate required gate while preserving the
remediation backlog.

`quality` retains its job ID, name and 20-minute timeout. After the existing
helper tests it runs Rustfmt, Clippy, ShellCheck installation and verification,
then ShellCheck analysis. Analysis first runs the complete informational scan
at `--severity=style`, writes all findings and counts, then runs the same file
list with `--severity=error`. A blocking finding or tool failure fails
`quality`. The existing `agent-ci` aggregate requires `quality == success`,
so such a failure also prevents aggregate success.

Only ShellCheck exit codes `0` (completed without findings) and `1` (completed
with findings) are valid for the informational scan. All other exit codes,
missing executables, invalid JSON and inconsistent findings/status fail analysis.
The blocking scan propagates every nonzero exit code. See the
[v0.11.0 manual](https://github.com/koalaman/shellcheck/blob/v0.11.0/shellcheck.1.md)
for interpreter selection and exit-code definitions.

Every completed informational scan prints every finding to the job log and
writes `reports/shellcheck/findings.json`, `summary.json` and `summary.md`.
The summary includes the complete file inventory, severity and rule counts,
version, archive checksum, analyzed SHA, run ID and attempt. Counts also appear
in the Actions job summary. The pinned upload action retains
`agent-shellcheck-<sha>-<run>-<attempt>` for 90 days, including when the
subsequent blocking scan fails. An attempted analysis without evidence also
fails the upload step. No ShellCheck job or `continue-on-error` is added.

The threshold is a fixed code setting, with no automatic fallback or baseline
allowlist. In a separate remediation delivery, address the actionable warnings
first, remeasure the complete scope and review changing the threshold to
`warning`. Review that follow-up during Phase 9 evidence verification before
promotion. After warnings are resolved or individually reviewed, consider
`info` and then `style` through explicit changes with positive and negative CI
evidence at each threshold. New findings never lower the threshold automatically.

### 5.4. Exclusions

**Accepted exclusions: none.** All 27 files and all default rule findings remain
in scope. This delivery adds no disable directives, rule exclusions or
repository-wide suppressions.

Any future exclusion must be reviewed individually and recorded here with the
exact file or narrow scope, rule ID, technical justification and the name of the
person accepting it. Prefer correcting the script. Runtime assumptions and
deferred lower-severity findings above are not accepted exclusions.

### 5.5. Local verification and pending CI acceptance

Local checks use the pinned official binary as an ordinary user. Reports are
local evidence and do not establish GitHub Actions acceptance.

| Check | Local result |
| --- | --- |
| Implemented installer against the official release | Passed: archive checksum and installed `0.11.0` verified |
| Complete analysis and error gate | Passed: 27 files, baseline counts unchanged, zero blocking findings |
| CI helper/workflow regression suite | 33 tests passed, including download/extraction failure, checksum mismatch before extraction, wrong version, invalid reports, exit codes `2`/`3`/`4` and execution failure |
| Recursive discovery and required maintenance inputs | Covered by regression tests, including paths with spaces, empty scope and missing maintenance scripts |
| Required aggregate failure handling | Existing aggregate command rejects failed, skipped, cancelled and missing required results |
| Real blocking probe in an isolated copy | A new nested plugin produced `SC1049`, `SC1050`, `SC1072` and `SC1073`; analysis failed and the actual `agent-ci` command rejected the resulting quality failure |
| New clean plugin and static-only analysis | Passed: automatically reported 28 files; a script containing a `touch` command did not create its marker |
| Interpreter probe in an isolated copy | Array syntax reported `SC3030` in POSIX `preinst`; the same array syntax in a Bash plugin produced no finding |
| Real missing-input and executable probes | Analysis rejected missing `postrm` and a nonexistent ShellCheck executable |
| Workflow YAML, Python syntax and patch whitespace | Passed; mandatory order, timeout and aggregate dependencies verified |

Run the installed helper locally using:

```bash
SHELLCHECK=/path/to/verified/shellcheck python3 .github/scripts/shellcheck-ci.py analyze
python3 -m unittest discover -s .github/scripts -p 'test_*.py' -v
```

Implementation commit, PR, corresponding Actions run/artifact links, reviewer
and acceptance date are **pending**. The integration is implemented and tested
locally; it is **not yet validated in CI**.

- [ ] Record the implementation commit/PR and a successful Actions `quality`
  execution with its ShellCheck artifact and all 27 files.
- [ ] Introduce an error-level finding in a temporary nested plugin revision;
  verify `quality` and `agent-ci` both fail in Actions and retain the evidence.
- [ ] Remove the probe, verify the required checks succeed and record both run
  references. Confirm shebang-based interpreter selection and the file inventory.
- [ ] Review the lower-severity remediation follow-up and any proposed
  exclusions before progressively tightening the threshold.

## 6. Test reports and reference coverage — API modernization Phase 2

This implements Issue #238, Phase 3 in the Agent roadmap above. It follows the
aggregate-only reporting approach in FWCloud API `ENS`
[`scripts/ci-reports.cjs`](https://github.com/soltecsis/fwcloud-api/blob/ENS/scripts/ci-reports.cjs),
using Python's standard library for XML, JSON, hashing and validation.

### 6.1. Pinned tools and installation

| Input | Exact version | Installation |
| --- | --- | --- |
| Rust / Cargo | `1.99.1` | Existing shared Phase 1 action |
| LLVM tools | `llvm-tools-preview` from Rust `1.99.1` | `rustup component add --toolchain 1.99.1 llvm-tools-preview` |
| `cargo-nextest` | `0.9.151` | Official Linux x86_64 release archive |
| `cargo-llvm-cov` | `0.9.1` | Official Linux x86_64 release archive |

`.github/report-tools.toml` pins the complete download URLs and SHA-256 digests.
`scripts/install-report-tools.py` verifies each archive before reading its single
regular binary, installs under `$RUNNER_TEMP/agent-report-tools/bin`, verifies the
CLI release, and adds it to `GITHUB_PATH`. Archives are never extracted wholesale.
The release digests were checked against GitHub's official release asset API.
Installation does not compile Cargo utilities or resolve their dependencies.

The exact release manifests declare minimum Rust versions
[`1.91` for Nextest](https://github.com/nextest-rs/nextest/blob/cargo-nextest-0.9.151/Cargo.toml)
and [`1.87` for cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov/blob/v0.9.1/Cargo.toml).
Both were exercised with Rust `1.99.1` locally. LLVM is taken from that compiler,
not from an independently versioned system installation. The workflow continues
to use `ubuntu-24.04` x86_64. Other architectures require separately reviewed pins.

### 6.2. One test execution, discovery and doctests

`scripts/test_ci.py build` removes old test/coverage/JUnit outputs, cleans LLVM
workspace coverage data, builds instrumented binaries without running test
bodies, and compares Cargo and Nextest listings. Cargo dependency resolution uses
`--locked` throughout. `show-env` supplies the same instrumentation to the build
and discovery commands. `CARGO_LLVM_COV_TARGET_DIR` is explicitly `target/` for
both the build and execution; otherwise LLVM's wrapper chooses a different
directory and recompiles dependencies. The Cargo cache has a reporting-tool
suffix separate from quality builds. Raw profiles produced by discovery are
removed before execution. Report directories and counters are never reused as
coverage evidence from the cache.

The only command that executes test bodies is:

```bash
cargo llvm-cov nextest --profile ci --locked --no-tests=fail --no-report
```

The CI profile in `../.config/nextest.toml` disables fail-fast and retries,
stores failure output, suppresses successful output, and reports all skipped
tests. It uses one test thread because existing tests share
`./etc/openvpn_status_sampling.json`; `serial_test` mutexes do not synchronize
the separate processes created by Nextest. Parallel execution exposed three
filesystem races locally. Serial execution passed all 93 tests; no tests were
removed, skipped or retried to obtain that result.

Cargo and Nextest both discover **93 tests across 18 binaries** on the tracked
application baseline. `cargo test --doc --locked -- --list` discovers **zero
doctests**, consistent with the original Actions log. Listings execute no test
bodies. Each CI execution compares the complete test-name multiset, records its
SHA-256 and count, and requires zero doctests. New doctests therefore fail the
discovery check with an explicit policy message until their execution and
reporting are implemented; they are never silently omitted by Nextest.

Five former inline `#[cfg(test)] mod tests` bodies are moved unchanged into
`src/config_tests.rs`, `src/utils/files_list_tests.rs`,
`src/utils/http_files_tests.rs`, `src/utils/openvpn_dir_tests.rs` and
`src/workers/openvpn_status_collector_tests.rs`. `#[path]` keeps their original
module names and private-item access. Their bodies were compared with the
pre-migration source after deindentation and Rustfmt reflow; they match exactly.
This allows stable LLVM coverage to exclude test code without disabling tests
or enabling nightly coverage attributes.

### 6.3. Coverage scope, formats and policy

After the one execution, `scripts/test_ci.py reports` attempts every export,
even if another export or the runner failed. It uses only `cargo llvm-cov report`
and never reruns tests. All exports and the console gate use identical filename
exclusions: tests, examples, benchmarks, generated/build/vendor paths and
`*_tests.rs` / `*-tests.rs`, in addition to LLVM's default dependency exclusions.
The validator requires original tracked `.rs` files under `src/`.

| Report | Path |
| --- | --- |
| Nextest JUnit source | `target/nextest/ci/junit.xml` |
| Published JUnit | `reports/tests/junit.xml` |
| Command results, discovery and phase durations | `reports/tests/execution.json` |
| LCOV | `reports/coverage/lcov.info` |
| Native LLVM JSON, without redundant functions | `reports/coverage/coverage.json` |
| Derived aggregate line metrics and minimum | `reports/coverage/coverage-summary.json` |
| HTML report and its assets | `reports/coverage/html/index.html` |
| Coverage identity, checksum and validation | `reports/coverage/analysis.json` |
| Aggregate execution metadata | `reports/metadata.json` |

The existing minimum remains **line coverage >= 20%**. The console command
`cargo llvm-cov report --fail-under-lines 20` enforces it, and the validator
independently applies the same minimum to unrounded native JSON aggregate line
metrics. Zero executable lines, missing data and calculation failures fail CI.
Dependencies and test-only files cannot increase the gated percentage.

Rust `1.99.1` exports LLVM JSON `3.1.0`; the validator also understands the `2.x`
layout with the same required fields. LLVM counts macro expansion lines in
LCOV `LF`/`LH` and JSON summaries; the number of physical `DA` records may be
smaller. Validation checks physical line ranges and coverage bounds, then
compares every file's declared LCOV totals with native JSON and sums the totals.
It preserves LLVM's measurements and never creates artificial source lines.

LCOV source paths and JSON file names are normalized only after verifying their
absolute paths lie inside the resolved checkout root. Paths outside that root,
traversal, absolute published LCOV paths, symlinks, missing originals, untracked
generated sources and nonapplication paths fail validation. Published LCOV uses
only `SF:src/...rs`, retaining original line numbers for the planned Phase 7
SonarQube import. No SonarQube job or import acceptance is claimed here.

The tracked obsolete `cobertura.xml` is deleted. `/cobertura.xml` and `/reports/`
are ignored. Each run regenerates its coverage from fresh counters.

### 6.4. Validation, provenance and failure handling

`scripts/ci_reports.py` verifies JUnit XML structure, declared and actual counts,
at least one executed test, failures, skips and suite errors. DTD/entity payloads
are rejected. It requires successful recorded clean/build/discovery/test/export/
normalization/gate commands and complete execution metadata; a passing partial
JUnit cannot hide a failed or interrupted runner. Every command's exit status
remains separate, and the workflow has no `continue-on-error` on these stages.

The validator also requires LCOV, valid JSON aggregate/file metrics, HTML,
positive executable source coverage, the 20% minimum, agreement between formats,
and SHA-256 digests bound to the produced reports. It derives
`coverage-summary.json`, `metadata.json` and `analysis.json` during validation.
Invalid or missing evidence generates failed metadata and fails the job.

The actual `git rev-parse HEAD` must match `ANALYSIS_COMMIT`, and Git must confirm
the checkout root. Metadata records repository, commit, event/ref, run ID,
attempt, Rust/Cargo/runner/coverage-tool versions, command/test status, counts,
coverage, timings and validation errors. PR checkouts retain the PR head as
their analyzed commit; `GITHUB_SHA`'s synthetic merge commit is never substituted.
Execution records from another commit, run, attempt or tool version are rejected.

Only after normalization are the exact published LCOV bytes hashed.
`analysis.json` records that SHA-256, producing attempt, identity, versions,
coverage, test status, validation result and `accepted_baseline`. Existing
analysis with a different identity, producer or checksum is rejected. Only a
complete successful validation sets `accepted_baseline: true`; forceful runner
termination leaves failure/incomplete evidence, never an accepted baseline.

`GITHUB_STEP_SUMMARY` contains only the analyzed commit, aggregate test counts,
execution status, line percentage, minimum and validation status. Individual
test names, assertions, stack traces and source code are excluded from it and
from validation error messages. JUnit may contain failure details; artifact
visibility and organization privacy/retention review remain applicable.

### 6.5. Artifacts and gates

Both uploads run under `always()`, request 90-day retention, reject absent upload
inputs, and use immutable `actions/upload-artifact` commit
`ea165f8d65b6e75b540449e92b4886f43607fa02` (`v4.6.2`).

- `agent-tests-<RUN_ID>-<ATTEMPT>` contains `tests/` (JUnit and execution receipt)
  and `metadata.json`, under the common `reports/` upload root.
- `agent-coverage-<RUN_ID>` contains the contents of `reports/coverage/` and uses
  `overwrite: true`. `analysis.json` identifies the actual producing attempt.

Available failed evidence is retained without changing the original test or
coverage failure. A later job may consume an earlier valid producing attempt of
the same run if the producer was not rerun; its consumer must verify identity,
accepted status and checksum. If the producer is rerun and fails, its overwritten
artifact is failed evidence and cannot become a fallback baseline. Forceful
termination may prevent uploads entirely and does not waive validation.

The separate `coverage` job is removed. Both DEB and RPM depend on `agent-ci`
and `security_audit`; coverage now gates packages through `agent-ci -> test`.
External publication remains restricted to the existing main-push conditions.

### 6.6. Reference measurements and outstanding hosted acceptance

The reported **667 seconds is not an established baseline**. Actual successful
GitHub Actions executions were inspected on 2026-11-06:

| Previous run | Analyzed revision | Test job | Coverage job | Sum |
| --- | --- | --- | --- | --- |
| [42184497510](https://github.com/soltecsis/fwcloud-agent/actions/runs/42184497510) | `2b2d4777bfc079dfc3bad710c410e74a6e1baeff` | 42 s | 587 s | 629 s |
| [42178784330](https://github.com/soltecsis/fwcloud-agent/actions/runs/42178784330) | `2cdfefcef2a6cc887baa979971872de36e21ddf6` | 188 s | 495 s | 683 s |
| [42029990388](https://github.com/soltecsis/fwcloud-agent/actions/runs/42029990388) | `d35bcd1b5b8ce5d8da67a4dddc3d66763804941b` | 195 s | 460 s | 655 s |

The primary reference is attempt 1 of run `42184497510`, using `ubuntu-24.04`,
runner image `20261101.360.1`, Rust `1.99.1`, Tarpaulin `0.37.5`, and the same
93-test application suite. Its logs report **60.90% (721/1,184 lines)**.
The subsequent application base `127ebb9` merges that ShellCheck-only change.

| Primary reference component | Measured duration / source |
| --- | --- |
| Previous standalone test setup | 22 s, Actions step timestamps |
| Previous standalone application build | 4 s, Actions step timestamps |
| Previous test step including test compilation | 12 s, Actions step timestamps |
| Coverage tool installation | 149.21 s, log timestamps from package install to completion |
| Complete coverage setup including toolchain/cache/environment artifact | 174 s, Actions step timestamps |
| Coverage application compilation | 170.03 s, log `Building project` to `Finished test` |
| Traced execution and collection | About 235.09 s, build completion to coverage results |
| Coverage summary / XML generation | Included in the 405 s coverage step; no separate reliable timer |
| Coverage artifact generation/upload | 1 s, Actions step timestamps |
| Previous jobs summed / longest job | 629 s / 587 s |
| Replacement hosted job and uploads | **Pending first execution of the implementation** |

Local verification uses `/tmp/fwcloud-agent-report-source`, exported from the
tracked application base plus these reporting changes, excluding unrelated
untracked application files. Rust and LLVM tools are isolated under `/tmp`;
compilation uses two workers and disables debug symbols to limit disk usage.
The local context uses synthetic run `1`/attempt `3` for validator exercises;
it is not a hosted run or evidence for a committed implementation revision.

| Local verification on 2026-11-06 | Result |
| --- | --- |
| Verified binary installation, LLVM already installed | 2.66 s |
| Initial instrumented cold build | 185.90 s |
| Cargo/Nextest discovery | 93 tests each; zero doctests; about 1.16 s warm |
| Corrected warm instrumented build | 0.47 s; execution reused it without recompiling |
| Single serial Nextest execution | 93 passed, zero failures/skips; 2.37 s runner / 2.93 s command |
| LCOV / JSON / HTML / console processing | About 0.76 s combined, before normalization/validation |
| Report validation | Passed; about 0.11 s |
| LLVM line coverage | **62.06% (1,086/1,750)**, minimum unchanged at 20% |
| Failed execution probe | 90 passed / 3 failed; JUnit and all coverage exports retained; validation failed and baseline rejected |
| Validator, runner, installer, performance and existing helper tests | 63 passed; negative coverage/report/provenance cases included |
| Real Nextest reporting fixture | One passed, one failed, one skipped; failure retained and successful output suppressed |
| Rustfmt / all-target Clippy with `-D warnings` | Passed after the module moves |
| Actionlint `1.7.7` | Passed |
| `Cargo.lock` | Unchanged |

The observed coverage difference is **+1.16 percentage points** versus hosted
Tarpaulin, with different executable line denominators. Instrumentation,
macro/async handling and test-code exclusion differ. This is a provisional
cross-environment comparison; it is not proof of a coverage improvement or an
accepted hosted reference baseline. The 20% minimum is unchanged.

The implementation is **not accepted as performance-complete** until comparable
hosted executions verify no increase. Installation avoids utility compilation;
instrumented build and execution share the same target directory; caches remain
optional. Timings for clean/build/discovery/test/each export/normalization are
recorded in the execution receipt, installation in `reports/ci/report-tools.json`,
and validation in `metadata.json`. Actions step timestamps provide setup and
artifact generation/upload times.

After publishing the implementation for CI, capture comparable runs and use:

```bash
gh run view 42184497510 --repo soltecsis/fwcloud-agent --json jobs,headSha,url > previous.json
gh run view <NEW_RUN_ID> --repo soltecsis/fwcloud-agent --json jobs,headSha,url > replacement.json
python3 .github/scripts/ci_performance.py previous.json replacement.json
```

The comparison rejects incomplete/failed runs and reports both summed job time
and the previous longest job to expose a wall-time regression hidden by adding
parallel jobs. Record cold/warm cache state, runner image, exact implementation
SHA, tool installation, compilation, execution, report processing and both
uploads. Investigate regressions before closing this phase.

- [ ] Record implementation commit/PR, successful hosted run and reviewed artifacts.
- [ ] Verify failed-test, missing-report and sub-20% probes fail hosted `test` and `agent-ci`.
- [ ] Confirm artifact overwrite/rerun identity and visibility/retention behavior in GitHub.
- [ ] Record a validated hosted LLVM baseline, checksum and Tarpaulin comparison.
- [ ] Measure replacement hosted cold/warm runs against the reference and confirm no regression.
- [ ] Record reviewer and acceptance date. Local timings do not satisfy these items.

## 7. Phase 4 — Isolated system-management route tests

### 7.1. Verified starting baseline and historical comparison

On 2026-11-06, the Issue 3 reporting implementation from PR #249 was rerun
against the tracked application at `dcede7742d3bf3814c65856a4eb3d5f84298e8f8`.
A clean export under `/tmp/fwcloud-agent-239-baseline` excluded the pre-existing,
untracked OpenVPN configuration-install work. It passed all **93 tests**;
JUnit, LCOV, LLVM JSON, HTML, the 20% gate and provenance validation succeeded.
The local report uses snapshot `87143af6063b2bb96523de411fc145673d5a416f` and
synthetic run `239`/attempt `1`; this is local evidence, not a GitHub run.
The baseline used harmless `ip`/`iptables-save` command stubs so its existing
endpoint-existence tests could not inspect the host network/firewall.

The actual hosted Issue 3
[run 42195925541](https://github.com/soltecsis/fwcloud-agent/actions/runs/42195925541)
also completed successfully. Its
[coverage artifact 13492396227](https://github.com/soltecsis/fwcloud-agent/actions/runs/42195925541/artifacts/13492396227),
`agent-coverage-42195925541`, was downloaded and inspected. `analysis.json`
identifies PR #249 head `1f2aa1dbeaa2cd9d82cbf9e623cbe28475169635`, attempt 1,
Rust/Cargo `1.99.1`, Nextest `0.9.151`, cargo-llvm-cov `0.9.1`, successful tests
and validation, and `accepted_baseline: true`. The downloaded ZIP matches
GitHub's SHA-256 `8e8fe5b648d6d091cc38e88161486ef3b901941da7a29472b9434969e5c5859f`;
its LCOV matches `analysis.json` digest
`068267fd6bc979ad2f17f947872d090aec77470761ef080509784008be99cf15`.
The hosted aggregate is **62.06% (1,086/1,750)**. Every route-file measurement
matches the fresh local starting baseline below. The local aggregate is
**61.94% (1,084/1,750)**: the two differing covered lines are in the real command
backend, consistent with the controlled `ip`/`iptables-save` outputs.

The April figures supplied in Issue #239 were approximately 24.2% for routes,
0% for daemon/IPSec/WireGuard/WebSocket, and 12.9% for OpenVPN. Fresh LLVM
measurements confirm the four zero-coverage files, but measure routes at
**40.82% (189/463)** and OpenVPN at **38.99% (85/218)**. Historical Cobertura
values are context only: instrumentation, executable-line accounting and the
suite changed. Neither the old XML nor these differences establish current
coverage or an improvement attributable to this delivery.

### 7.2. Priorities and implemented behavior

The starting report had no executed daemon, IPSec, WireGuard or WebSocket
handler lines. OpenVPN upload only exercised missing data, and remove/read/status
successes and their filesystem effects were largely absent. File writes,
deletions, traversal and authorization were prioritized before longer-running
or privileged operations.

`tests/common/mod.rs` continues to call the real `fwcloud_agent::run` bootstrap.
Each `spawn_app` owns a server on `127.0.0.1:0`, a `TempDir` beneath
`tests/playground/tmp/`, explicit configuration/staging/data/plugin/policy paths,
its WebSocket map and a recording command executor. `Config::with_runtime_dirs`
uses owned paths and defaults without reading environment variables or loading,
rewriting or creating a real `.env`. Production `Config::new` retains its existing
environment initialization and real command executor. No working-directory or
process-environment change is needed by integration fixtures.

A dedicated server thread lets fixture destruction stop and join the server
synchronously, including during assertion unwinding. An owned collector guard
signals shutdown, wakes its receive timeout and joins the worker before the
fixture directory is removed. Collector unit tests also use separate persisted
configuration and cache directories; they no longer share `./etc` or set API
configuration environment variables. Existing sampling route tests use fixture
status paths. Nextest's CI concurrency is now four, with retries still disabled.
Explicit fixture tests verify simultaneous apps, same-name file independence,
closed listeners and cleanup during a panic.

Shared file-request matrices in `tests/common/files.rs` are called by daemon,
IPSec, WireGuard and the existing OpenVPN test modules. They verify new and
replacement uploads, file contents and mode, idempotent removal, malformed or
missing multipart/JSON, missing fields, invalid file metadata, invalid directories,
traversal, symlink destinations, and invalid batches. Snapshots include existing
files, permissions, directories and staging files, so rejected requests cannot
silently alter fixtures. Every family tests missing/invalid API keys and a
non-allowed peer IP with API validation explicitly enabled; valid requests use
a valid key and allowed loopback IP.

OpenVPN tests additionally exercise plain-text reads and real-time status,
empty/malformed raw status text, missing files, one-file constraints, cached CSV
formatting, bounded cache consumption and missing/empty caches. Sampling
configuration coverage is retained and isolated. No new request or worker reads a real
OpenVPN installation. Authorization tests cover reads, cache consumption,
sampling updates and update notifications as well as upload/removal.

The placeholder WebSocket test is replaced by nine real protocol tests using
Reqwest's HTTP upgrade with Actix's existing client-mode WebSocket codec. They
check the RFC handshake response, initial UUID, ping/pong, client close, transport
drop, streamed output, completion, invalid upgrades/UUIDs/durations, unknown IDs,
authorization and connection-map cleanup. Expiry is exercised with an isolated
old timestamp. The limit test seeds state records instead of live connections.
The longest requested test duration is one second; reads and cleanup have bounded
timeouts. No heartbeat or two-hour expiry wait is required.

All route command paths use an injected `CommandExecutor`, including systemctl,
plugins, interface/firewall queries, policy scripts and directory ownership.
The test implementation records requests and returns controlled output without
spawning a child. A systemctl regression verifies the exact requested restart
arguments and zero command calls for every authorization rejection. Targeted
file/WebSocket tests also assert zero command calls where applicable.

Tests exposed and now guard production fixes: multipart parser/chunk errors
propagate instead of being discarded or unwrapped; staging files are registered
before fallible writes; destination creation waits until validation completes;
filename traversal and symlink paths are rejected before any batch deletion or
upload commit; missing/invalid parameters return 400, and unknown WebSocket IDs
return 404. Error messages are serialized as valid JSON. Invalid upgrades no
longer allocate map entries; closed/finished actors remove their entries; the
WebSocket test handler yields during its bounded delays. Production authentication
is unchanged. These validation/status changes intentionally tighten prior error
behavior, including requests previously returning 500.

### 7.3. Resulting coverage and remaining branches

All values below are executable LLVM line counts from fresh validated reports;
no coverage exclusion was added or changed.

| Route source | Fresh starting baseline | After implementation |
| --- | --- | --- |
| `src/routes/daemon.rs` | 0/12 (0.00%) | 12/12 (100.00%) |
| `src/routes/fwcloud_script.rs` | 10/12 (83.33%) | 10/12 (83.33%) |
| `src/routes/info.rs` | 13/14 (92.86%) | 13/14 (92.86%) |
| `src/routes/interfaces.rs` | 4/4 (100.00%) | 4/4 (100.00%) |
| `src/routes/ipsec.rs` | 0/25 (0.00%) | 25/25 (100.00%) |
| `src/routes/iptables_save.rs` | 4/4 (100.00%) | 4/4 (100.00%) |
| `src/routes/openvpn.rs` | 85/218 (38.99%) | 167/222 (75.23%) |
| `src/routes/ping.rs` | 4/4 (100.00%) | 4/4 (100.00%) |
| `src/routes/plugin.rs` | 65/76 (85.53%) | 65/76 (85.53%) |
| `src/routes/systemctl.rs` | 4/7 (57.14%) | 11/11 (100.00%) |
| `src/routes/wireguard.rs` | 0/27 (0.00%) | 25/27 (92.59%) |
| `src/routes/ws.rs` | 0/60 (0.00%) | 61/62 (98.39%) |
| **All route files** | **189/463 (40.82%)** | **401/473 (84.78%)** |

Application line coverage increases from **61.94% (1,084/1,750)** to
**81.11% (1,533/1,890)** in the controlled local comparison. The count increase
reflects the configuration, validation and resource-lifecycle code. The mandatory
minimum remains **20%** in both the exporter and report validator.

No `src/routes/` source file remains at 0%. Remaining uncovered branches have
these explicit follow-up decisions:

- OpenVPN directory ensure/removal and SHA-256 handler successes remain follow-up
  behavioral coverage; the directory ownership path now accepts the recording
  executor, so future tests can check `chown` arguments without changing ownership.
  Unit coverage of directory validation/removal and hashing is retained. Separate
  zero-value branches for sampling line/cache limits can extend existing sampling
  matrices without invoking external tools.
- Policy-script success and plugin WebSocket streaming remain follow-up tests
  against the command recorder. Real script execution, package/service changes
  and the real command backend (`src/utils/cmd.rs`, 0% after injection) are
  deliberately unexecuted in this route suite. They remain in the coverage
  denominator; command-output parsing/error behavior needs dedicated controlled
  backend tests before claiming coverage of those operations.
- WebSocket's future-clock error arm is uncovered; expiry, closure, missing IDs,
  malformed upgrades and the connection limit are covered. WireGuard's two
  uncovered lines are multi-line debug-log arguments; both handlers and their
  successful filesystem effects execute. No exclusion is justified for these lines.
- This suite does not prove protection against an external process racing path
  validation with a symlink replacement. Descriptor-relative filesystem operations
  would be a separate hardening change. Missing raw status files retain the
  existing I/O-error response (500); missing cached status returns its CSV header.
  The raw-status endpoints intentionally return text without parsing it; existing
  collector unit tests cover malformed structured records.

### 7.4. Reproduction and evidence

With the pinned toolchain/reporting tools installed, the normal validation is:

```bash
cargo test --locked
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
python3 -m unittest discover -s .github/scripts -p 'test_*.py' -q
```

The existing CI workflow automatically discovers the new test binaries and still
uses Issue 3's `test_ci.py build`, `test_ci.py test`, `test_ci.py reports` and
`ci_reports.py` stages with the actual Actions identity. Cargo and Nextest both
discover **127 tests**, zero doctests, and the instrumented run passes all 127
with no failures, skips or retries. Test execution takes about 4.02 seconds
locally with four Nextest processes; this is not a hosted performance comparison.
The 63 CI helper tests and all-target Clippy pass. Resources under the verification
checkout's `tests/playground/tmp/` return to only `.gitkeep` after execution.
Local execution uses UID 1000 and needs no root or Linux capabilities; the local
Codex sandbox needs permission to open loopback listeners.

The implementation was exported to `/tmp/fwcloud-agent-239-result`, excluding
pre-existing untracked `src/utils/openvpn_config.rs`,
`tests/openvpn_server_configs_install.rs` and `.omc/`. Those files were left
unchanged. The unfinished untracked install test targets a route absent from this
change and is not included in the reported suite. The validated implementation
snapshot is `07e2a9d25f6688d0b1df4b1a3a9046198778e6e2`, synthetic run `239`/attempt
`1`; it is not a published implementation revision or Actions execution.

The first implementation export was rejected by scope validation because a
shared build directory still held binaries from the baseline checkout. Cleaning
application build artifacts and running the entire reporting workflow again
produced the accepted evidence below. No extra filename exclusion or validator
relaxation was used. These results supersede that rejected export.

Local evidence is retained under ignored `reports/system-routes/baseline/` and
`reports/system-routes/after/`, each containing `tests/junit.xml`,
`tests/execution.json`, `coverage/lcov.info`, `coverage/coverage.json`,
`coverage/coverage-summary.json`, `coverage/html/index.html`,
`coverage/analysis.json` and `metadata.json`. Source paths are normalized and the
validator accepted both reports. LCOV SHA-256 values are:

- Before: `e346e18b265f187d9578fc5877216a464f67491efce4651bc7d6ddf71a97ff1f`.
- After: `1cfffd2c137435907f8951e6cc2a0af2413b25384423919ffba7485845c0a7ea`.

The hosted baseline run and artifact above are verified. A hosted execution of
**this implementation** remains pending publication of its commit/PR. Record its
actual `agent-tests-<RUN_ID>-<ATTEMPT>` and `agent-coverage-<RUN_ID>` links,
`analysis.json` identity/checksum, runner image and review outcome here before
closing hosted acceptance. The earlier Issue 3 run and synthetic local receipt
must not be represented as execution of these new tests on GitHub.

## 8. Updating this record

Update this document with each delivery. Record the exact revision, commands,
environment, results, limitations, PR/run/artifact links and reviewer. Keep
implemented behavior separate from planned controls and GitHub acceptance.
Retest affected checks after changes and do not reuse results from an earlier
revision without establishing their applicability.
