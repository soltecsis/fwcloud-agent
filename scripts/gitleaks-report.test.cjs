const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const { test } = require('node:test');
const root = path.resolve(__dirname, '..');
const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
const PRIVATE = 'DO_NOT_EXPOSE_THIS_VALUE';
const FINDING = { RuleID: 'generic-api-key', Secret: PRIVATE, Match: PRIVATE,
  File: `src/${PRIVATE}.rs`, StartLine: 987654, EndLine: 987655, Commit: PRIVATE,
  Fingerprint: PRIVATE, Description: PRIVATE, Author: PRIVATE, Email: PRIVATE };

function collect(t, report, code, overrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-report-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const raw = path.join(dir, 'raw.json');
  const output = path.join(dir, 'metadata.json');
  const summary = path.join(dir, 'summary.md');
  if (report !== undefined) fs.writeFileSync(raw, typeof report === 'string' ? report : JSON.stringify(report));
  const result = spawnSync(process.execPath, [path.join(__dirname, 'gitleaks-report.cjs')], {
    cwd: root, encoding: 'utf8', env: { ...process.env,
      ANALYSIS_COMMIT: head, GITHUB_REPOSITORY: 'soltecsis/fwcloud-agent',
      GITHUB_RUN_ID: '240', GITHUB_RUN_ATTEMPT: '1', GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_STEP_SUMMARY: summary, GITLEAKS_REPORT_PATH: raw, GITLEAKS_METADATA_PATH: output,
      GITLEAKS_EXIT_CODE: String(code), GITLEAKS_LOG_BYTES: '0', GITLEAKS_VERSION: '8.30.1',
      GITLEAKS_SCOPE: 'full-history', GITLEAKS_COMMIT_COUNT: '5', GITLEAKS_LOG_OPTS: '--all',
      ...overrides,
    },
  });
  assert.equal(fs.existsSync(raw), false, 'raw report must be deleted');
  const metadata = JSON.parse(fs.readFileSync(output, 'utf8'));
  const published = JSON.stringify(metadata) + fs.readFileSync(summary, 'utf8') + result.stdout + result.stderr;
  assert.ok(!published.includes(PRIVATE));
  assert.ok(!published.includes('StartLine') && !published.includes('987654'));
  return { result, metadata, published };
}

test('complete empty scan publishes only approved aggregate fields', t => {
  const { result, metadata } = collect(t, [], 0);
  assert.equal(result.status, 0);
  assert.equal(metadata.status, 'success');
  assert.equal(metadata.findingCount, 0);
  assert.deepEqual(Object.keys(metadata).sort(), [
    'schemaVersion', 'collectedAt', 'repository', 'commit', 'event', 'runId', 'runAttempt',
    'gitleaksVersion', 'scanScope', 'logOptions', 'commitCount', 'packageType', 'packageSha256',
    'exitCode', 'scannerLogBytes', 'status', 'findingCount', 'ruleIds', 'errors',
  ].sort());
});
test('exit 1 with findings fails after sanitized evidence publication', t => {
  const { result, metadata } = collect(t, [FINDING, FINDING], 1);
  assert.equal(result.status, 1);
  assert.equal(metadata.status, 'findings');
  assert.equal(metadata.findingCount, 2);
  assert.deepEqual(metadata.ruleIds, ['generic-api-key']);
});
test('missing, malformed and non-array reports fail without exposing input', t => {
  for (const report of [undefined, PRIVATE, `{${PRIVATE}`, {}, [null], ['finding'], [{ RuleID: PRIVATE }]]) {
    const { result, metadata } = collect(t, report, 0);
    assert.equal(result.status, 1);
    assert.equal(metadata.status, 'error');
  }
});
test('inconsistent evidence and scanner errors cannot become ordinary findings', t => {
  for (const [report, code] of [[[], 1], [[FINDING], 0], [[], 2], [[FINDING], 126]]) {
    const { result, metadata } = collect(t, report, code);
    assert.equal(result.status, 1);
    assert.equal(metadata.status, 'error');
  }
  for (const code of ['', '-1', '1.0', 'NaN', '256', '999999999999999999999999']) {
    assert.equal(collect(t, [], code).metadata.status, 'error');
  }
});
test('diagnostics fail empty and partially completed scans', t => {
  for (const [report, code] of [[[], 0], [[FINDING], 1]]) {
    for (const bytes of ['', '-1', '1', PRIVATE]) {
      assert.equal(collect(t, report, code, { GITLEAKS_LOG_BYTES: bytes }).metadata.status, 'error');
    }
  }
});
test('missing or invalid context and scan metadata fail closed', t => {
  for (const overrides of [
    { ANALYSIS_COMMIT: '0'.repeat(40) }, { ANALYSIS_COMMIT: '' },
    { GITHUB_RUN_ID: PRIVATE }, { GITHUB_RUN_ATTEMPT: '' },
    { GITHUB_REPOSITORY: PRIVATE }, { GITHUB_EVENT_NAME: PRIVATE },
    { GITLEAKS_SCOPE: PRIVATE }, { GITLEAKS_VERSION: PRIVATE },
    { GITLEAKS_LOG_OPTS: PRIVATE }, { GITLEAKS_COMMIT_COUNT: PRIVATE },
  ]) assert.equal(collect(t, [], 0, overrides).metadata.status, 'error');
});
test('distribution metadata requires a valid package type and checksum', t => {
  for (const kind of ['deb', 'rpm']) {
    const valid = { GITLEAKS_SCOPE: 'distribution', GITLEAKS_PACKAGE_TYPE: kind,
      GITLEAKS_PACKAGE_SHA256: 'a'.repeat(64), GITLEAKS_LOG_OPTS: '', GITLEAKS_COMMIT_COUNT: '' };
    assert.equal(collect(t, [], 0, valid).metadata.status, 'success');
    for (const extra of [{ GITLEAKS_PACKAGE_TYPE: PRIVATE }, { GITLEAKS_PACKAGE_SHA256: PRIVATE }])
      assert.equal(collect(t, [], 0, { ...valid, ...extra }).metadata.status, 'error');
  }
});

test('pre-scan failures retain fixed diagnostics and never publish arbitrary error text', t => {
  for (const category of ['unsafe_package_member', 'scan_preparation_failed', PRIVATE]) {
    const { result, metadata } = collect(t, [], 0, { GITLEAKS_PRE_SCAN_ERROR: category });
    assert.equal(result.status, 1);
    assert.equal(metadata.status, 'error');
    assert.deepEqual(metadata.errors, [category === PRIVATE ? 'invalid_pre_scan_error' : category]);
  }
});
