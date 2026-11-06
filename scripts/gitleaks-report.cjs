// Adapted from FWCloud API. Detailed findings never leave this collector.
const fs = require('node:fs');
const { context, writeJson, summary, exitCode: integer } = require('./ci-context.cjs');
const rules = new Set(require('./gitleaks-rule-ids.json'));
const VERSION = '8.30.1';
const SCOPES = ['pull-request', 'push', 'new-branch-history', 'full-history', 'distribution'];

function collect(env = process.env) {
  const errors = [];
  let identity = { schemaVersion: 1, commit: null, runId: null, runAttempt: null };
  try {
    identity = context('.', { ...env, ANALYSIS_COMMIT: '' });
    if (!env.ANALYSIS_COMMIT || identity.commit !== env.ANALYSIS_COMMIT)
      errors.push('checkout_mismatch');
  } catch { errors.push('invalid_ci_context'); }
  let findings = null;
  try {
    const parsed = JSON.parse(fs.readFileSync(env.GITLEAKS_REPORT_PATH, 'utf8'));
    if (!Array.isArray(parsed)) throw new Error();
    findings = parsed;
  } catch { errors.push('invalid_or_missing_report'); }
  finally {
    // Deletion failure is fatal: publication must never retain raw evidence.
    if (env.GITLEAKS_REPORT_PATH) fs.rmSync(env.GITLEAKS_REPORT_PATH, { force: true });
  }
  const ruleIds = new Set();
  for (const finding of findings ?? []) {
    if (!finding || typeof finding !== 'object' || !rules.has(finding.RuleID))
      errors.push('invalid_finding');
    else ruleIds.add(finding.RuleID);
  }
  const exitCode = integer(env.GITLEAKS_EXIT_CODE);
  const scannerLogBytes = integer(env.GITLEAKS_LOG_BYTES);
  const findingCount = findings?.length ?? null;
  if (exitCode === null || exitCode > 255) errors.push('invalid_exit_code');
  else if (![0, 1].includes(exitCode)) errors.push('scanner_execution_failed');
  else if ((exitCode === 0 && findingCount > 0) || (exitCode === 1 && findingCount === 0))
    errors.push('inconsistent_result');
  // Gitleaks can return 0 after a Git error, or 1 after a partial scan with findings.
  if (scannerLogBytes === null || scannerLogBytes > 0) errors.push('scanner_diagnostics');
  const scanScope = SCOPES.includes(env.GITLEAKS_SCOPE) ? env.GITLEAKS_SCOPE : null;
  if (!scanScope) errors.push('invalid_scope');
  if (env.GITLEAKS_VERSION !== VERSION) errors.push('invalid_version');
  const commitCount = integer(env.GITLEAKS_COMMIT_COUNT);
  const logOptions = /^(--all|[0-9a-f]{40}(\.\.[0-9a-f]{40})?)$/.test(env.GITLEAKS_LOG_OPTS || '')
    ? env.GITLEAKS_LOG_OPTS : null;
  const packageType = ['deb', 'rpm'].includes(env.GITLEAKS_PACKAGE_TYPE) ? env.GITLEAKS_PACKAGE_TYPE : null;
  const packageSha256 = /^[0-9a-f]{64}$/.test(env.GITLEAKS_PACKAGE_SHA256 || '')
    ? env.GITLEAKS_PACKAGE_SHA256 : null;
  if (scanScope === 'distribution') {
    if (!packageType || !packageSha256) errors.push('invalid_package_metadata');
  } else if (commitCount === null || !logOptions) errors.push('invalid_history_metadata');
  const status = errors.length ? 'error' : findingCount ? 'findings' : 'success';
  return {
    ...identity, gitleaksVersion: env.GITLEAKS_VERSION === VERSION ? VERSION : null,
    scanScope, logOptions, commitCount, packageType, packageSha256,
    exitCode, scannerLogBytes, status, findingCount,
    ruleIds: [...ruleIds].sort(), errors: [...new Set(errors)].sort(),
  };
}

function main() {
  const env = process.env;
  const metadata = collect(env);
  writeJson(env.GITLEAKS_METADATA_PATH || 'reports/secrets/metadata.json', metadata);
  if (env.GITHUB_OUTPUT) fs.appendFileSync(env.GITHUB_OUTPUT, 'metadata_ready=true\n');
  summary([
    '## Secret detection', '',
    `Commit: \`${metadata.commit || 'unavailable'}\``,
    `CI execution: \`${metadata.runId || 'unavailable'}/${metadata.runAttempt || 'unavailable'}\``,
    `Scan category: \`${metadata.scanScope || 'unavailable'}${metadata.packageType ? ` (${metadata.packageType})` : ''}\``,
    `Gitleaks: \`${metadata.gitleaksVersion || 'unavailable'}\``,
    `Outcome: **${metadata.status.toUpperCase()}**`,
    `Findings: **${metadata.findingCount ?? 'unavailable'}**`,
    ...(metadata.ruleIds.length ? [`Rules: ${metadata.ruleIds.map(r => `\`${r}\``).join(', ')}`] : []),
  ]);
  if (metadata.status !== 'success') process.exitCode = 1;
}

if (require.main === module) {
  try { main(); }
  catch { console.error('Secret evidence publication failed.'); process.exitCode = 1; }
}
module.exports = { collect };
