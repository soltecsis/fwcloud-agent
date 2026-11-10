"""Exercise the actual aggregate command, including absent and skipped jobs."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap
from types import SimpleNamespace
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / "workflows/main.yml"


class AggregateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = WORKFLOW.read_text()
        aggregate = workflow.split("\n  agent-ci:\n", 1)[1].split("\n  deb-package:\n", 1)[0]
        cls.required = re.search(r"needs: \[([^\]]+)\]", aggregate).group(1).split(", ")
        cls.aggregate = aggregate
        cls.command = textwrap.dedent(aggregate.split("python3 - <<'PY'\n", 1)[1].split("          PY", 1)[0])

    def invoke(self, results, sonar_required="true"):
        return subprocess.run(
            [sys.executable, "-c", self.command],
            env={**os.environ, "REQUIRED_RESULTS": json.dumps(results),
                 "SONAR_REQUIRED": sonar_required, "GITHUB_STEP_SUMMARY": os.devnull},
            capture_output=True, text=True,
        )

    def successful_results(self):
        return {job: {"result": "success"} for job in self.required}

    def test_all_required_jobs_succeed(self):
        result = self.invoke(self.successful_results())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_all_mandatory_controls_are_required_even_after_failure(self):
        self.assertEqual(set(self.required), {"quality", "test", "security_audit", "secrets", "sca", "sonar", "deb-package", "rpm-package"})
        self.assertIn("if: ${{ always() }}", self.aggregate)
        self.assertNotIn("continue-on-error", self.aggregate)

    def test_each_non_success_result_blocks(self):
        for job in self.required:
            for outcome in ("failure", "cancelled", "skipped", "", None):
                with self.subTest(job=job, outcome=outcome):
                    results = self.successful_results()
                    results[job]["result"] = outcome
                    self.assertNotEqual(self.invoke(results).returncode, 0)

    def test_missing_job_or_result_blocks(self):
        for job in self.required:
            with self.subTest(job=job):
                results = self.successful_results()
                del results[job]
                self.assertNotEqual(self.invoke(results).returncode, 0)
                results[job] = {}
                self.assertNotEqual(self.invoke(results).returncode, 0)

    def test_unexpected_jobs_block(self):
        results = self.successful_results()
        results["unreviewed"] = {"result": "success"}
        self.assertNotEqual(self.invoke(results).returncode, 0)

    def test_only_explicitly_optional_sonar_may_be_skipped(self):
        results = self.successful_results()
        results["sonar"]["result"] = "skipped"
        self.assertEqual(self.invoke(results, "false").returncode, 0)
        for state in ("success", "failure", "cancelled", "", None):
            results["sonar"]["result"] = state
            self.assertNotEqual(self.invoke(results, "false").returncode, 0)
        results["sonar"]["result"] = "skipped"
        for job in set(self.required) - {"sonar"}:
            failed = dict(results, **{job: {"result": "skipped"}})
            self.assertNotEqual(self.invoke(failed, "false").returncode, 0)


class PackagingGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        jobs = WORKFLOW.read_text().split("\njobs:\n", 1)[1]
        sections = re.split(r"^  ([\w-]+):\n", jobs, flags=re.MULTILINE)
        cls.jobs = dict(zip(sections[1::2], sections[2::2]))

    def needs(self, job):
        return set(re.search(r"needs: \[([^\]]+)\]", self.jobs[job]).group(1).split(", "))

    def test_packages_preserve_audit_and_coverage_gates(self):
        for job in ("deb-package", "rpm-package"):
            with self.subTest(job=job):
                self.assertEqual(self.needs(job), {"quality", "test", "security_audit", "secrets", "sca", "sonar"})
                gate = self.jobs[job].split("steps:", 1)[0]
                for required in ("quality", "test", "security_audit", "secrets", "sca"):
                    self.assertIn(f"needs.{required}.result == 'success'", gate)
                self.assertIn("needs.sonar.result == 'success'", gate)
                self.assertIn("needs.sonar.result == 'skipped'", gate)
                self.assertIn("github.event_name == 'pull_request'", gate)

    def test_dependency_graph_does_not_reference_removed_jobs(self):
        self.assertNotIn("checks", self.jobs)
        self.assertNotIn("build", self.jobs)
        self.assertNotIn("coverage", self.jobs)
        for job, section in self.jobs.items():
            if "needs:" in section:
                with self.subTest(job=job):
                    self.assertLessEqual(self.needs(job), self.jobs.keys())

    def test_dependency_graph_is_acyclic(self):
        def visit(job, active):
            self.assertNotIn(job, active)
            for dependency in self.needs(job) if 'needs:' in self.jobs[job] else []:
                visit(dependency, active | {job})
        for job in self.jobs:
            visit(job, set())

    def test_packages_are_scanned_before_approved_artifacts_are_uploaded(self):
        for kind in ['deb', 'rpm']:
            section = self.jobs[kind + '-package']
            self.assertLess(section.index('uses: ./.github/actions/scan-secrets'),
                            section.index('name: Upload ' + kind.upper() + ' package'))
            self.assertIn('kind: ' + kind, section)
            self.assertIn('report-directory: reports/secrets-' + kind, section)
            self.assertNotIn('continue-on-error', section)

    def test_publication_remains_restricted_to_main_pushes_after_packages(self):
        publishers = ("deb-to-fwcloud", "rpm-to-fwcloud",
                      "deb-to-packagecloud", "rpm-to-packagecloud")
        for job in publishers:
            with self.subTest(job=job):
                self.assertEqual(self.needs(job), {"agent-ci", "deb-package", "rpm-package"})
                self.assertIn("github.event_name == 'push'", self.jobs[job])
                self.assertIn("github.ref == 'refs/heads/main'", self.jobs[job])
                self.assertIn("github.repository == 'soltecsis/fwcloud-agent'", self.jobs[job])
        for job, section in self.jobs.items():
            if job not in publishers and job != "sonar":
                with self.subTest(job=job):
                    self.assertNotRegex(section, r"(?<![\w.])secrets\.")


class ShellCheckWorkflowTests(unittest.TestCase):
    def test_shellcheck_is_mandatory_after_rust_quality_checks(self):
        quality = WORKFLOW.read_text().split("\n  quality:\n", 1)[1].split("\n  security_audit:\n", 1)[0]
        commands = (
            "cargo fmt --all -- --check",
            "python3 .github/scripts/sonar_ci.py clippy",
            "python3 .github/scripts/shellcheck-ci.py install",
            "python3 .github/scripts/shellcheck-ci.py analyze",
        )
        positions = [quality.index(command) for command in commands]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("name: FWCloud-Agent Quality", quality)
        self.assertIn("timeout-minutes: 20", quality)
        self.assertNotIn("continue-on-error", quality)
        for step in quality.split("      - name: ")[1:]:
            if "shellcheck-ci.py" in step:
                self.assertNotIn("if:", step)
        self.assertIn("always() && steps.shellcheck.outcome != 'skipped'", quality)
        self.assertIn("path: reports/shellcheck/", quality)
        self.assertIn("if-no-files-found: error", quality)


class ReportingWorkflowTests(unittest.TestCase):
    def test_reports_and_both_uploads_run_after_failed_execution(self):
        section = WORKFLOW.read_text().split("\n  test:\n", 1)[1].split("\n  secrets:\n", 1)[0]
        self.assertNotIn("continue-on-error", section)
        self.assertIn("always() && steps.test_build.outcome != 'skipped'", section)
        self.assertIn("python3 .github/scripts/ci_reports.py", section)
        self.assertIn("name: agent-tests-${{ github.run_id }}-${{ github.run_attempt }}", section)
        self.assertIn("name: agent-coverage-${{ github.run_id }}", section)
        self.assertIn("overwrite: true", section)
        self.assertEqual(section.count("if-no-files-found: error"), 2)
        for name in ("Validate test and coverage evidence", "Upload test evidence", "Upload coverage evidence"):
            step = section.split("      - name: " + name, 1)[1].split("      - name:", 1)[0]
            self.assertIn("if: ${{ always() }}", step)

    def test_suite_execution_is_consolidated_and_actions_remain_immutable(self):
        workflow = WORKFLOW.read_text()
        self.assertNotIn("\n  coverage:\n", workflow)
        self.assertEqual(workflow.count("python3 .github/scripts/test_ci.py test"), 1)
        self.assertNotIn("cargo tarpaulin", workflow)
        for action in re.findall(r"uses: ([^\s]+)", workflow):
            if not action.startswith("./"):
                self.assertRegex(action, r"@[0-9a-f]{40}$")


class SecretsWorkflowTests(unittest.TestCase):
    def test_history_job_uses_exact_head_full_history_and_no_credentials(self):
        section = WORKFLOW.read_text().split('\n  secrets:\n', 1)[1].split('\n  sca:\n', 1)[0]
        self.assertIn('name: FWCloud-Agent Secrets', section)
        self.assertIn('timeout-minutes: 15', section)
        self.assertIn('ref: ${{ env.ANALYSIS_COMMIT }}', section)
        self.assertIn('fetch-depth: 0', section)
        self.assertIn('persist-credentials: false', section)
        self.assertIn('kind: history', section)
        self.assertIn('agent-secrets-${{ github.run_id }}-${{ github.run_attempt }}', section)
        self.assertNotIn('secrets.', section)

    def test_private_reports_are_removed_before_metadata_only_publication(self):
        action = (WORKFLOW.parents[1] / 'actions/scan-secrets/action.yml').read_text()
        self.assertNotIn('continue-on-error', action)
        self.assertIn('always() && steps.cleanup.outcome', action)
        self.assertIn("steps.secret_report.outputs.metadata_ready == 'true'", action)
        self.assertLess(action.index('name: Remove detailed secret evidence'),
                        action.index('name: Publish sanitized secret evidence'))
        self.assertIn('path: ${{ inputs.report-directory }}/metadata.json', action)
        self.assertIn('if-no-files-found: error', action)
        self.assertIn('retention-days: 90', action)
        self.assertIn('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02', action)
        self.assertIn("if: ${{ inputs.kind == 'history' }}", action)
        self.assertIn("RUN_SECRET_INTEGRATION: '1'", action)

    def test_both_report_helper_and_ci_unit_tests_are_in_quality(self):
        quality = WORKFLOW.read_text().split('\n  quality:\n', 1)[1].split('\n  security_audit:\n', 1)[0]
        self.assertIn('node --test scripts/gitleaks-report.test.cjs', quality)
        self.assertIn("python3 -m unittest discover -s .github/scripts -p 'test_*.py'", quality)


class SonarWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        PackagingGateTests.setUpClass.__func__(cls)

    needs = PackagingGateTests.needs

    def test_sonar_transfers_native_reports_and_only_uploads_aggregate_receipt(self):
        section = self.jobs["sonar"]
        self.assertEqual(self.needs("sonar"), {"quality", "test", "security_audit", "secrets", "sca"})
        self.assertIn("fetch-depth: 0", section)
        self.assertIn("agent-coverage-${{ github.run_id }}", section)
        self.assertIn("agent-clippy-${{ github.run_id }}", section)
        self.assertIn("scannerVersion: 8.1.0.6389", section)
        self.assertIn("skipSignatureVerification: false", section)
        self.assertIn("path: reports/sonar/metadata.json", section)
        self.assertNotIn("path: .scannerwork", section)
        self.assertNotIn("continue-on-error", section)
        settings = (WORKFLOW.parents[2] / "sonar-project.properties").read_text()
        self.assertIn("sonar.qualitygate.wait=true", settings)
        self.assertIn("sonar.rust.lcov.reportPaths=coverage-input/lcov.info", settings)
        self.assertIn("sonar.rust.clippyReport.reportPaths=clippy-input/clippy.json", settings)
        self.assertNotIn("sonar.coverage.exclusions", settings)
        self.assertNotIn("vars.SONAR_PROJECT_KEY", section)
        self.assertNotIn("vars.SONAR_REFERENCE_BRANCH", section)
        self.assertNotIn("vars.SONAR_ORGANIZATION", section)
        self.assertIn("sonar.organization=soltecsis", settings)
        self.assertIn("sonar.projectKey=soltecsis_fwcloud-agent", settings)
        self.assertNotIn("pull_request_target", WORKFLOW.read_text())

    def test_fork_dependabot_policy_and_package_failures(self):
        def condition(job):
            expression = self.jobs[job].split("if: >-", 1)[1].split("runs-on:", 1)[0].strip()
            expression = expression.removeprefix("${{").removesuffix("}}").replace("!cancelled()", "not cancelled()").replace("&&", " and ").replace("||", " or ")
            return " ".join(expression.split())
        for event, fork, actor, user in (
            ("push", False, "developer", "developer"),
            ("workflow_dispatch", False, "developer", "developer"),
            ("pull_request", False, "developer", "developer"),
            ("pull_request", True, "developer", "developer"),
            ("pull_request", False, "developer", "dependabot[bot]"),
            ("pull_request", False, "dependabot[bot]", "developer"),
            ("push", False, "dependabot[bot]", "developer"),
        ):
            github = SimpleNamespace(actor=actor, event_name=event, repository="test/agent", event=SimpleNamespace(
                pull_request=SimpleNamespace(head=SimpleNamespace(repo=SimpleNamespace(full_name="fork/agent" if fork else "test/agent")),
                                             user=SimpleNamespace(login=user))))
            required = actor != "dependabot[bot]" and (event != "pull_request" or not fork and user != "dependabot[bot]")
            namespace = {"github": github, "cancelled": lambda: False}
            self.assertEqual(eval(condition("sonar"), {"__builtins__": {}}, namespace), required)
            for job in ("deb-package", "rpm-package"):
                needs = SimpleNamespace(**{name: SimpleNamespace(result="success") for name in self.needs(job)})
                namespace["needs"] = needs
                for outcome in ("success", "skipped", "failure", "cancelled"):
                    needs.sonar.result = outcome
                    self.assertEqual(eval(condition(job), {"__builtins__": {}}, namespace),
                                     outcome == "success" or outcome == "skipped" and not required)
                needs.sonar.result = "success" if required else "skipped"
                for name in self.needs(job) - {"sonar"}:
                    for outcome in ("failure", "skipped", "cancelled"):
                        getattr(needs, name).result = outcome
                        self.assertFalse(eval(condition(job), {"__builtins__": {}}, namespace))
                    getattr(needs, name).result = "success"


if __name__ == "__main__":
    unittest.main()
