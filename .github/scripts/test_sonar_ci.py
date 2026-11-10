"""Positive and negative Sonar provenance, scanner context and gate contracts."""

from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import sonar_ci as sonar


class SonarTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ("src", "tests", ".github", "coverage-input", "clippy-input"):
            (self.root / directory).mkdir()
        for name in ("rust-toolchain.toml", ".github/report-tools.toml", "sonar-project.properties"):
            (self.root / name).write_bytes((sonar.ROOT / name).read_bytes())
        (self.root / "src/main.rs").write_text("fn main() {}\n")
        (self.root / "coverage-input/lcov.info").write_text("SF:src/main.rs\nDA:1,1\nLF:1\nLH:1\nend_of_record\n")
        (self.root / "clippy-input/clippy.json").write_text('{"reason":"build-finished","success":true}\n')
        self.env = {"ANALYSIS_COMMIT": "a" * 40, "GITHUB_REPOSITORY": "test/agent", "GITHUB_RUN_ID": "100",
                    "GITHUB_RUN_ATTEMPT": "3", "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/ENS",
                    "GITHUB_REF_NAME": "ENS", "SONAR_PROJECT_KEY": "test_agent", "SONAR_REFERENCE_BRANCH": "devel",
                    "GITHUB_OUTPUT": str(self.root / "output"), "GITHUB_STEP_SUMMARY": str(self.root / "summary")}
        ci = {"repository": "test/agent", "source_commit": "a" * 40, "run_id": "100", "run_attempt": "2",
              "event": "push", "ref": "refs/heads/ENS"}
        self.rust = tomllib.loads((self.root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        pins = tomllib.loads((self.root / ".github/report-tools.toml").read_text())
        self.coverage = {**ci, "producer_attempt": "2", "accepted_baseline": True, "test_status": "success",
                         "validation_status": "success", "validation_errors": [],
                         "lcov_sha256": sonar.sha(self.root / "coverage-input/lcov.info"),
                         "versions": {"rustc": self.rust, "cargo": self.rust,
                                      "cargo-nextest": pins["cargo-nextest"]["version"],
                                      "cargo-llvm-cov": pins["cargo-llvm-cov"]["version"]}}
        self.lint = {**ci, "status": "success", "exit_code": 0, "rust": self.rust,
                     "report_sha256": sonar.sha(self.root / "clippy-input/clippy.json")}
        self.save()
        mocked = patch.object(sonar.subprocess, "check_output", side_effect=self.output)
        mocked.start()
        self.addCleanup(mocked.stop)

    def output(self, command, **kwargs):
        if command == ["git", "rev-parse", "HEAD"]:
            return "a" * 40
        if command[:2] == ["git", "ls-files"]:
            return "src/main.rs\0"
        if command == ["rustc", "--version"]:
            return f"rustc {self.rust} (fixture 2026-11-10)\n"
        self.fail(f"Unexpected subprocess: {command}")

    def save(self):
        sonar.write(self.root / "coverage-input/analysis.json", self.coverage)
        sonar.write(self.root / "clippy-input/analysis.json", self.lint)

    def test_verified_previous_attempt_inputs_and_branch_args(self):
        result = sonar.prepare(self.root, self.env)
        self.assertEqual(result["coverageProducerAttempt"], "2")
        self.assertEqual(result["clippyProducerAttempt"], "2")
        args = (self.root / "output").read_text()
        self.assertIn("-Dsonar.branch.name=ENS", args)
        self.assertIn("-Dsonar.newCode.referenceBranch=devel", args)
        self.assertNotIn("pullrequest", args)

    def test_pull_request_uses_base_not_branch_analysis(self):
        self.env.update(GITHUB_EVENT_NAME="pull_request", GITHUB_REF="refs/pull/1/merge",
                        GITHUB_HEAD_REF="feature/sonar", GITHUB_BASE_REF="ENS", PR_NUMBER="1")
        for report in (self.coverage, self.lint):
            report.update(event="pull_request", ref="refs/pull/1/merge")
        self.save()
        sonar.prepare(self.root, self.env)
        args = (self.root / "output").read_text()
        self.assertIn("-Dsonar.pullrequest.base=ENS", args)
        self.assertIn("-Dsonar.pullrequest.branch=feature/sonar", args)
        self.assertNotIn("sonar.branch.name", args)
        self.assertNotIn("newCode.referenceBranch", args)

    def test_reference_branch_does_not_reference_itself(self):
        sonar.prepare(self.root, {**self.env, "SONAR_REFERENCE_BRANCH": "ENS"})
        self.assertNotIn("newCode.referenceBranch", (self.root / "output").read_text())

    def test_missing_project_key_reference_or_injected_args_fail(self):
        for change in ({"SONAR_PROJECT_KEY": ""}, {"SONAR_REFERENCE_BRANCH": ""},
                       {"SONAR_PROJECT_KEY": "x -Dsonar.qualitygate.wait=false"},
                       {"GITHUB_REF_NAME": "x\ninjected"}, {"ANALYSIS_COMMIT": "b" * 40}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                sonar.prepare(self.root, {**self.env, **change})

    def test_foreign_failed_or_future_producers_rejected(self):
        for kind in ("coverage", "lint"):
            original = copy.deepcopy(getattr(self, kind))
            for change in ({"repository": "other/repo"}, {"source_commit": "b" * 40}, {"run_id": "101"},
                           {"event": "workflow_dispatch"}, {"ref": "refs/heads/other"},
                           {"run_attempt": "4"}, {"run_attempt": "0"}, {"run_attempt": "invalid"}):
                with self.subTest(kind=kind, change=change):
                    setattr(self, kind, {**original, **change})
                    self.save()
                    with self.assertRaises(ValueError):
                        sonar.prepare(self.root, self.env)
            setattr(self, kind, original)
            self.save()
        for change in ({"accepted_baseline": False}, {"test_status": "failed_or_incomplete"},
                       {"validation_errors": ["failed"]}, {"validation_status": "failed"},
                       {"producer_attempt": "1"}, {"versions": {}}):
            with self.subTest(change=change):
                sonar.write(self.root / "coverage-input/analysis.json", {**self.coverage, **change})
                with self.assertRaises(ValueError):
                    sonar.prepare(self.root, self.env)
        self.save()
        for change in ({"status": "error"}, {"exit_code": 1}, {"rust": "wrong"}):
            with self.subTest(change=change):
                sonar.write(self.root / "clippy-input/analysis.json", {**self.lint, **change})
                with self.assertRaises(ValueError):
                    sonar.prepare(self.root, self.env)

    def test_missing_or_tampered_reports_fail(self):
        for directory, filename in (("coverage-input", "lcov.info"), ("clippy-input", "clippy.json")):
            file = self.root / directory / filename
            original = file.read_bytes()
            file.write_bytes(original + b"tampered")
            with self.assertRaises(ValueError):
                sonar.prepare(self.root, self.env)
            file.unlink()
            with self.assertRaises((OSError, ValueError)):
                sonar.prepare(self.root, self.env)
            file.write_bytes(original)

    def test_coverage_scope_and_source_symlinks_fail_even_with_valid_hash(self):
        file = self.root / "coverage-input/lcov.info"
        for source in ("../secret.rs", "/tmp/secret.rs", "src/missing.rs", "tests/test.rs"):
            file.write_text(f"SF:{source}\nDA:1,1\nLF:1\nLH:1\nend_of_record\n")
            self.coverage["lcov_sha256"] = sonar.sha(file)
            self.save()
            with self.subTest(source=source), self.assertRaises(ValueError):
                sonar.prepare(self.root, self.env)
        (self.root / "src/link.rs").symlink_to(self.root / "src/main.rs")
        with self.assertRaises(ValueError):
            sonar.prepare(self.root, self.env)

    def test_clippy_incomplete_failed_or_error_messages_rejected(self):
        file = self.root / "clippy-input/clippy.json"
        for text in ("", "{}\n", '{"reason":"build-finished","success":false}\n',
                     '{"reason":"compiler-message","message":{"level":"error"}}\n'
                     '{"reason":"build-finished","success":true}\n'):
            file.write_text(text)
            self.lint["report_sha256"] = sonar.sha(file)
            self.save()
            with self.subTest(text=text), self.assertRaises(ValueError):
                sonar.prepare(self.root, self.env)

    def test_actual_clippy_command_preserves_native_failure_and_receipt(self):
        for code in (0, 1):
            def run(command, **kwargs):
                self.assertEqual(command, ["cargo", "clippy", "--all-targets", "--locked", "--message-format=json",
                                           "--", "-D", "warnings"])
                kwargs["stdout"].write(json.dumps({"reason": "build-finished", "success": code == 0}) + "\n")
                return subprocess.CompletedProcess(command, code)
            with self.subTest(code=code), patch.object(sonar.subprocess, "run", side_effect=run):
                self.assertEqual(sonar.clippy(self.root, self.env), code)
                receipt = json.loads((self.root / "reports/clippy/analysis.json").read_text())
                self.assertEqual(receipt["status"], "success" if code == 0 else "error")
                self.assertEqual(receipt["exit_code"], code)

    def test_record_is_aggregate_only_and_requires_successful_preparation(self):
        sonar.prepare(self.root, self.env)
        with redirect_stdout(io.StringIO()):
            result = sonar.record(self.root, {**self.env, "PREPARE_OUTCOME": "success", "SCAN_OUTCOME": "success"})
            self.assertEqual(result["qualityGate"], "PASSED")
            for outcome in ("failure", "cancelled", "skipped"):
                result = sonar.record(self.root, {**self.env, "PREPARE_OUTCOME": "success", "SCAN_OUTCOME": outcome})
                self.assertEqual(result["qualityGate"], "FAILED_OR_INCOMPLETE")
            result = sonar.record(self.root, {**self.env, "PREPARE_OUTCOME": "failure", "SCAN_OUTCOME": "success"})
            self.assertEqual(result["qualityGate"], "FAILED_OR_INCOMPLETE")
        self.assertNotIn("clippy.json", json.dumps(result))

    def test_task_links_do_not_publish_arbitrary_urls_or_secrets(self):
        sonar.prepare(self.root, self.env)
        task = self.root / ".scannerwork/report-task.txt"
        task.parent.mkdir()
        for url in ("https://evil.invalid/dashboard?id=x", "https://user:secret@sonarcloud.io/dashboard",
                    "https://sonarcloud.io/dashboard?id=x&token=secret"):
            task.write_text("dashboardUrl=" + url + "\nceTaskId=secret\n")
            with redirect_stdout(io.StringIO()):
                result = sonar.record(self.root, {**self.env, "PREPARE_OUTCOME": "success", "SCAN_OUTCOME": "success"})
            self.assertNotIn("dashboardUrl", result)
            self.assertNotIn("secret", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
