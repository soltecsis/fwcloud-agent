"""Exercise runner failure propagation and verified binary extraction."""

import hashlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import ci_reports
import test_ci
import ci_performance


SPEC = importlib.util.spec_from_file_location("report_installer", Path(__file__).with_name("install-report-tools.py"))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def archive(self, *, link=False, name="cargo-nextest"):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as output:
            info = tarfile.TarInfo(name)
            if link:
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                output.addfile(info)
            else:
                info.size = 6
                output.addfile(info, io.BytesIO(b"binary"))
        return data.getvalue()

    def test_checksum_verified_before_extracting_regular_binary(self):
        archive = self.archive()
        digest = hashlib.sha256(archive).hexdigest()
        self.assertEqual(installer.binary(archive, digest, "cargo-nextest"), b"binary")
        with self.assertRaises(ValueError):
            installer.binary(archive, "0" * 64, "cargo-nextest")

    def test_missing_symlinked_or_traversing_binaries_rejected(self):
        for archive in (self.archive(link=True), self.archive(name="../cargo-nextest"), self.archive(name="other")):
            with self.assertRaises(ValueError):
                installer.binary(archive, hashlib.sha256(archive).hexdigest(), "cargo-nextest")


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.identity = {"source_commit": "a" * 40, "run_attempt": "1"}
        self.context_patch = patch.object(test_ci, "context", return_value=self.identity)
        self.context_patch.start()
        self.addCleanup(self.context_patch.stop)
        self.execution = test_ci.Execution(self.root, {}, fresh=True)
        self.execution.data["commands"]["discovery"] = {"exit_code": 0}

    def test_failed_test_status_retained_and_junit_copied(self):
        path = self.root / "target/nextest/ci/junit.xml"
        path.parent.mkdir(parents=True)
        path.write_text("<testsuite/>")
        with patch.object(test_ci.subprocess, "run", return_value=subprocess.CompletedProcess([], 100)) as run:
            self.assertEqual(self.execution.test(), 100)
        command = run.call_args.args[0]
        self.assertEqual(command, ["cargo", "llvm-cov", "nextest", "--profile", "ci", "--locked", "--no-tests=fail", "--no-report"])
        self.assertEqual(run.call_args.kwargs["env"]["CARGO_LLVM_COV_TARGET_DIR"], str(self.root / "target"))
        self.assertEqual((self.root / "reports/tests/junit.xml").read_text(), "<testsuite/>")
        self.assertEqual(self.execution.data["commands"]["test"]["exit_code"], 100)
        with self.assertRaises(ValueError):
            self.execution.test()

    def test_all_report_exports_attempted_after_each_failure(self):
        self.execution.data["commands"]["test"] = {"exit_code": 100}
        result = subprocess.CompletedProcess([], 1)
        with patch.object(test_ci.subprocess, "run", return_value=result) as run:
            self.assertEqual(self.execution.reports(), 1)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 4)
        self.assertTrue(all(cmd[:3] == ["cargo", "llvm-cov", "report"] for cmd in commands))
        self.assertIn("--fail-under-lines", commands[-1])
        self.assertEqual(commands[-1][-1], "20")
        self.assertEqual(self.execution.data["commands"]["test"]["exit_code"], 100)
        self.assertTrue(self.execution.data["completed"])

    def test_missing_command_status_cannot_be_accepted_as_completed_execution(self):
        with patch.object(test_ci.subprocess, "run", side_effect=OSError):
            code, _ = self.execution.command("test", ["missing-executable"])
        self.assertEqual(code, 127)
        self.assertEqual(self.execution.data["commands"]["test"]["exit_code"], 127)

    def test_fresh_execution_discards_stale_reports_and_junit(self):
        for name in ("reports/metadata.json", "reports/tests/stale.xml", "reports/coverage/stale.info", "target/nextest/ci/junit.xml"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("stale")
        test_ci.Execution(self.root, {}, fresh=True)
        for name in ("reports/metadata.json", "reports/tests/stale.xml", "reports/coverage/stale.info", "target/nextest/ci/junit.xml"):
            self.assertFalse((self.root / name).exists())

    def test_discovery_compares_names_and_rejects_new_doctests(self):
        import json
        listing = json.dumps({"rust-suites": {"lib": {"testcases": {"example": {}}}}})
        for cargo, docs, expected in (("example: test\n", "", 0), ("different: test\n", "", 1),
                                      ("example: test\n", "src/lib.rs - (line 1): test\n", 1), ("", "", 1)):
            with self.subTest(cargo=cargo, docs=docs):
                with patch.object(self.execution, "command", side_effect=[(0, cargo), (0, listing), (0, docs), (0, "")]):
                    self.execution.data["timings_seconds"] = dict(cargo_list=0, nextest_list=0, doctest_list=0)
                    self.assertEqual(self.execution.discover({}), expected)


class CheckoutContextTests(unittest.TestCase):
    def setUp(self):
        self.root = ci_reports.ROOT
        self.env = {"ANALYSIS_COMMIT": "a" * 40, "GITHUB_REPOSITORY": "soltecsis/fwcloud-agent",
                    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "pull_request",
                    "GITHUB_REF": "refs/pull/1/merge"}

    def output(self, args, root, env):
        return {("git", "rev-parse", "--show-toplevel"): str(root),
                ("git", "rev-parse", "HEAD"): "a" * 40,
                ("rustc", "--version"): "rustc 1.99.1 (hash date)",
                ("cargo", "--version"): "cargo 1.99.1 (hash date)",
                ("cargo", "nextest", "--version"): "cargo-nextest 0.9.151 (hash date)",
                ("cargo", "llvm-cov", "--version"): "cargo-llvm-cov 0.9.1"}[tuple(args)]

    def test_pr_merge_ref_is_not_used_in_place_of_actual_checkout(self):
        with patch.object(ci_reports, "command_output", side_effect=self.output):
            value = ci_reports.context(self.root, self.env | {"GITHUB_SHA": "b" * 40})
        self.assertEqual(value["source_commit"], "a" * 40)

    def test_wrong_checkout_or_installed_version_fails(self):
        for command in (("git", "rev-parse", "HEAD"), ("cargo", "nextest", "--version"), ("cargo", "llvm-cov", "--version")):
            with self.subTest(command=command):
                with patch.object(ci_reports, "command_output", side_effect=lambda args, root, env: "wrong" if tuple(args) == command else self.output(args, root, env)):
                    with self.assertRaises(ValueError):
                        ci_reports.context(self.root, self.env)


class PerformanceTests(unittest.TestCase):
    def run_data(self, durations):
        return {"url": "https://github.com/soltecsis/fwcloud-agent/actions/runs/1", "headSha": "a" * 40,
                "jobs": [{"name": name, "conclusion": "success", "startedAt": "2026-11-06T00:00:00Z",
                          "completedAt": f"2026-11-06T00:{seconds // 60:02d}:{seconds % 60:02d}Z", "steps": []}
                         for name, seconds in durations.items()]}

    def test_compare_aggregate_and_longest_job_to_avoid_hidden_wall_time_regression(self):
        old = self.run_data({ci_performance.TEST: 42, ci_performance.COVERAGE: 587})
        result = ci_performance.compare(old, self.run_data({ci_performance.TEST: 400}))
        self.assertEqual(result["previous_total_seconds"], 629)
        self.assertTrue(result["within_previous_total"])
        result = ci_performance.compare(old, self.run_data({ci_performance.TEST: 600}))
        self.assertTrue(result["within_previous_total"])
        self.assertFalse(result["within_previous_longest_job"])

    def test_failed_or_missing_jobs_are_not_performance_evidence(self):
        old = self.run_data({ci_performance.TEST: 42, ci_performance.COVERAGE: 587})
        new = self.run_data({ci_performance.TEST: 400})
        new["jobs"][0]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            ci_performance.compare(old, new)


if __name__ == "__main__":
    unittest.main()
