"""Fail-closed evidence probes; fixtures contain no project runtime dependencies."""

from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import ci_reports as ci


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.reports = self.root / "reports"
        self.identity = {
            "repository": "soltecsis/fwcloud-agent", "source_commit": "a" * 40,
            "run_id": "123", "run_attempt": "2", "event": "pull_request", "ref": "refs/pull/1/merge",
            "versions": {"rustc": "1.99.1", "cargo": "1.99.1", "cargo-nextest": "0.9.151", "cargo-llvm-cov": "0.9.1"},
        }
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("fn f() {}\n" * 10)
        self.put("tests/junit.xml", '<testsuites tests="2" failures="0" errors="0"><testsuite name="suite" tests="2" failures="0" errors="0" skipped="1"><testcase name="private-test"/><testcase name="ignored"><skipped/></testcase></testsuite></testsuites>')
        self.put("coverage/lcov.info", "SF:src/lib.rs\n" + "".join(f"DA:{n},{int(n <= 2)}\n" for n in range(1, 11)) + "LF:10\nLH:2\nend_of_record\n")
        lines = {"count": 10, "covered": 2, "percent": 20}
        self.native = {"type": "llvm.coverage.json.export", "version": "2.0.1", "data": [{
            "files": [{"filename": "src/lib.rs", "summary": {"lines": lines}}], "totals": {"lines": lines}}]}
        ci.write_json(self.reports / "coverage/coverage.json", self.native)
        self.put("coverage/html/index.html", "<!doctype html><html><body>Coverage</body></html>")
        self.execution = self.identity | {
            "completed": True, "discovery": {"tests": 2, "doctests": 0},
            "commands": {name: {"exit_code": 0} for name in (
                "clean", "build", "discovery", "profile_cleanup", "test", "lcov", "json", "html", "gate", "normalization")},
            "timings_seconds": {"test": 1},
        }
        self.seal()
        self.summary_path = self.root / "summary.md"
        self.env = {"GITHUB_STEP_SUMMARY": str(self.summary_path), "SECRET": "do-not-copy"}
        self.inventory_patch = patch.object(ci, "source_inventory", return_value={"src/lib.rs"})
        self.inventory_patch.start()
        self.addCleanup(self.inventory_patch.stop)

    def put(self, name, text):
        path = self.reports / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def seal(self):
        self.execution["report_sha256"] = {
            name: hashlib.sha256((self.reports / name).read_bytes()).hexdigest()
            for name in ("tests/junit.xml", "coverage/lcov.info", "coverage/coverage.json", "coverage/html/index.html")
            if (self.reports / name).is_file()}
        ci.write_json(self.reports / "tests/execution.json", self.execution)

    def validate(self, success=False):
        with patch.object(ci, "context", return_value=self.identity), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = ci.validate(self.root, self.env)
        self.assertEqual(code, 0 if success else 1)
        metadata = ci.read_json(self.reports / "metadata.json")
        analysis = ci.read_json(self.reports / "coverage/analysis.json")
        self.assertEqual(analysis["accepted_baseline"], success)
        self.assertEqual(metadata["validation_status"], "success" if success else "failed")
        return metadata, analysis

    def test_valid_reports_bind_checkout_attempt_versions_checksum_and_aggregate(self):
        metadata, analysis = self.validate(True)
        self.assertEqual(metadata["tests"], {"tests": 2, "passed": 1, "failed": 0, "errors": 0, "skipped": 1})
        self.assertEqual(metadata["coverage"]["percent"], 20)
        self.assertEqual(analysis["lcov_sha256"], hashlib.sha256((self.reports / "coverage/lcov.info").read_bytes()).hexdigest())
        self.assertEqual(analysis["producer_attempt"], "2")
        self.assertEqual(analysis["source_commit"], "a" * 40)
        self.assertNotIn("do-not-copy", json.dumps(metadata))
        self.assertNotIn("private-test", self.summary_path.read_text())

    def test_all_mandatory_reports_must_exist(self):
        for name in ("tests/junit.xml", "coverage/lcov.info", "coverage/coverage.json", "coverage/html/index.html", "tests/execution.json"):
            with self.subTest(name=name):
                path = self.reports / name
                data = path.read_bytes()
                path.unlink()
                self.validate()
                path.write_bytes(data)
                (self.reports / "coverage/analysis.json").unlink()

    def test_empty_malformed_zero_failed_error_and_inconsistent_junit_rejected(self):
        for data in ("", "<testsuites>", "<root/>", "<testsuites/>",
                     '<testsuite tests="0"/>', '<testsuite><testcase name="x"><skipped/></testcase></testsuite>',
                     '<testsuite><testcase name="x"><failure>secret assertion</failure></testcase></testsuite>',
                     '<testsuite errors="1"><error>stack trace</error></testsuite>',
                     '<testsuite><testcase name="x"><error/></testcase></testsuite>',
                     '<testsuite tests="2"><testcase name="x"/></testsuite>',
                     '<testsuite failures="1"><testcase name="x"/></testsuite>',
                     '<!DOCTYPE testsuite [<!ENTITY x "payload">]><testsuite/>'):
            with self.subTest(data=data):
                self.put("tests/junit.xml", data)
                self.seal()
                self.validate()
                (self.reports / "coverage/analysis.json").unlink()

    def test_test_command_failure_cannot_be_hidden_by_passing_junit(self):
        self.execution["commands"]["test"]["exit_code"] = 100
        self.seal()
        metadata, _ = self.validate()
        self.assertEqual(metadata["test_status"], "failed_or_incomplete")

    def test_every_command_and_incomplete_or_missing_runner_status_blocks(self):
        for name in self.execution["commands"]:
            with self.subTest(name=name):
                self.execution["commands"][name]["exit_code"] = 1
                self.seal()
                self.validate()
                self.execution["commands"][name]["exit_code"] = 0
                (self.reports / "coverage/analysis.json").unlink()
        self.execution["completed"] = False
        self.seal()
        self.validate()

    def test_unsafe_or_nonexistent_source_paths_rejected(self):
        for name in ("/tmp/evil.rs", str(self.root / "src/lib.rs"), "src/../src/lib.rs", "../src/lib.rs",
                     "src/missing.rs", "tests/test.rs", "src/generated/test.rs", "src/lib_tests.rs", "C:/src/lib.rs", "src\\lib.rs"):
            with self.subTest(name=name):
                path = self.reports / "coverage/lcov.info"
                path.write_text(path.read_text().replace("SF:" + path.read_text().splitlines()[0][3:], "SF:" + name, 1))
                self.seal()
                self.validate()
                (self.reports / "coverage/analysis.json").unlink()

    def test_normalize_only_verified_checkout_paths(self):
        path = self.reports / "coverage/lcov.info"
        path.write_text(path.read_text().replace("src/lib.rs", str(self.root / "src/lib.rs")))
        records = ci.lcov(path, self.root, True)
        self.assertIn("SF:src/lib.rs", path.read_text())
        self.native["data"][0]["files"][0]["filename"] = str(self.root / "src/lib.rs")
        ci.write_json(self.reports / "coverage/coverage.json", self.native)
        ci.coverage(self.reports / "coverage/coverage.json", records, self.root, True)
        self.seal()
        self.validate(True)
        for name in ("/tmp/outside.rs", str(self.root / "src/../src/lib.rs")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ci.source_path(name, self.root, True)

    def test_symlinked_source_rejected(self):
        (self.root / "src/link.rs").symlink_to(self.root / "src/lib.rs")
        with self.assertRaises(ValueError):
            ci.source_path("src/link.rs", self.root)

    def test_generated_source_with_an_ordinary_filename_is_rejected(self):
        (self.root / "src/build_output.rs").write_text("fn f() {}\n" * 10)
        path = self.reports / "coverage/lcov.info"
        path.write_text(path.read_text().replace("src/lib.rs", "src/build_output.rs"))
        self.native["data"][0]["files"][0]["filename"] = "src/build_output.rs"
        ci.write_json(self.reports / "coverage/coverage.json", self.native)
        self.seal()
        self.validate()

    def test_invalid_lcov_records_are_rejected(self):
        path = self.reports / "coverage/lcov.info"
        original = path.read_text()
        for data in ("", "SF:src/lib.rs\nend_of_record\n", "SF:src/lib.rs\nLF:10\nLH:2\nend_of_record\n", original.replace("LF:10", "LF:11"),
                     original.replace("LH:2", "LH:3"), original.replace("DA:1,1", "DA:1,-1"),
                     original.replace("DA:1,1", "DA:0,1"), original.replace("DA:1,1", "DA:99,1"),
                     original.replace("DA:1,1", "DA:1,1\nDA:1,1"), original.replace("end_of_record\n", ""),
                     original.replace("LF:10", "OTHER:10")):
            with self.subTest(data=data):
                path.write_text(data)
                self.seal()
                self.validate()
                (self.reports / "coverage/analysis.json").unlink()

    def test_below_twenty_percent_fails_even_with_a_successful_native_gate(self):
        path = self.reports / "coverage/lcov.info"
        path.write_text(path.read_text().replace("DA:2,1", "DA:2,0").replace("LH:2", "LH:1"))
        lines = self.native["data"][0]["totals"]["lines"]
        lines.update(covered=1, percent=10)
        ci.write_json(self.reports / "coverage/coverage.json", self.native)
        self.seal()
        self.validate()

    def test_invalid_json_totals_files_or_nonfinite_percentage_fails(self):
        for value in ("", "{", "{}", "[]", '{"type":"llvm.coverage.json.export","version":"3.1.0","data":[1]}', json.dumps(self.native).replace('"count": 10', '"count": 11'),
                      json.dumps(self.native).replace('"percent": 20', '"percent": NaN'),
                      json.dumps(self.native).replace("src/lib.rs", "/tmp/evil.rs")):
            with self.subTest(value=value):
                self.put("coverage/coverage.json", value)
                self.seal()
                self.validate()
                (self.reports / "coverage/analysis.json").unlink()

    def test_any_report_changed_after_production_fails(self):
        self.put("tests/junit.xml", '<testsuite><testcase name="replacement"/></testsuite>')
        self.validate()

    def test_stale_commit_run_attempt_or_versions_fail(self):
        original = copy.deepcopy(self.execution)
        for name in ("repository", "source_commit", "run_id", "run_attempt", "versions"):
            with self.subTest(name=name):
                self.execution = original | {name: "stale"}
                self.seal()
                self.validate()
                (self.reports / "coverage/analysis.json").unlink()

    def test_discovery_cannot_drop_tests_or_doctests(self):
        for discovery in ({"tests": 3, "doctests": 0}, {"tests": 2, "doctests": 1}):
            self.execution["discovery"] = discovery
            self.seal()
            self.validate()
            (self.reports / "coverage/analysis.json").unlink()

    def test_existing_analysis_checksum_and_attempt_are_checked(self):
        _, original = self.validate(True)
        for change in ({"lcov_sha256": "0" * 64}, {"producer_attempt": "1"}, {"source_commit": "b" * 40}):
            with self.subTest(change=change):
                ci.write_json(self.reports / "coverage/analysis.json", original | change)
                self.validate()

    def test_summary_contains_only_allowlisted_aggregate_fields(self):
        metadata, _ = self.validate(True)
        text = ci.summary(metadata | {"validation_errors": ["secret source code"], "test_name": "private-name"})
        for forbidden in ("private", "secret", "stack", "src/", "do-not-copy", "refs/pull"):
            self.assertNotIn(forbidden, text)
        for expected in ("Analyzed commit", "Passed", "Failed", "Skipped", "20%", "success"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
