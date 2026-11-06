"""Exercise ShellCheck integrity, scope discovery, reporting and failure policy."""

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("shellcheck_ci", Path(__file__).with_name("shellcheck-ci.py"))
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class ShellCheckCiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "plugins/nested directory").mkdir(parents=True)
        self.plugin = self.root / "plugins/nested directory/example script.sh"
        self.plugin.write_text("#!/bin/bash\necho ok\n")
        (self.root / ".deb/maintainer-scripts").mkdir(parents=True)
        for name in ci.MAINTAINER_SCRIPTS:
            (self.root / ".deb/maintainer-scripts" / name).write_text("#!/bin/sh\nexit 0\n")
        self.env = {
            **os.environ,
            "RUNNER_TEMP": str(self.root),
            "GITHUB_ENV": str(self.root / "env"),
            "GITHUB_STEP_SUMMARY": str(self.root / "step-summary"),
        }
        self.finding = {
            "file": self.plugin.relative_to(self.root).as_posix(),
            "line": 2, "column": 6, "level": "warning", "code": 2154,
            "message": "variable is referenced but not assigned",
        }

    def run_analysis(self, comments=None, *, status=None, output=None, failure=None):
        comments = [self.finding] if comments is None else comments
        status = int(bool(comments)) if status is None else status

        def execute(command, **kwargs):
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, f"version: {ci.VERSION}\n", "")
            if "--severity=style" in command:
                return subprocess.CompletedProcess(
                    command, status, json.dumps({"comments": comments}) if output is None else output, "",
                )
            if failure:
                raise subprocess.CalledProcessError(failure, command)
            return subprocess.CompletedProcess(command, 0)

        with patch.object(ci.subprocess, "run", side_effect=execute) as run:
            with redirect_stdout(io.StringIO()):
                ci.analyze("/verified/shellcheck", self.env, self.root)
        return run.call_args_list

    def test_new_nested_scripts_and_all_extensionless_maintainers_are_included(self):
        new = self.root / "plugins/new.sh"
        new.write_text("#!/bin/sh\nexit 0\n")
        files = ci.discover(self.root)
        self.assertEqual(len(files), 6)
        self.assertIn(new.relative_to(self.root).as_posix(), files)
        self.assertIn(self.finding["file"], files)
        for name in ci.MAINTAINER_SCRIPTS:
            self.assertIn(f".deb/maintainer-scripts/{name}", files)

    def test_missing_or_empty_plugin_scope_fails_despite_maintainers(self):
        self.plugin.unlink()
        with self.assertRaisesRegex(ValueError, "No plugin"):
            ci.discover(self.root)
        (self.root / "plugins/nested directory").rmdir()
        (self.root / "plugins").rmdir()
        with self.assertRaisesRegex(ValueError, "Missing plugins"):
            ci.discover(self.root)

    def test_missing_each_maintainer_fails(self):
        for name in ci.MAINTAINER_SCRIPTS:
            with self.subTest(name=name):
                path = self.root / ".deb/maintainer-scripts" / name
                original = path.read_text()
                path.unlink()
                with self.assertRaisesRegex(ValueError, "Missing Debian"):
                    ci.discover(self.root)
                path.write_text(original)

    def test_discovery_permission_errors_propagate(self):
        def walk(_path, *, onerror):
            onerror(PermissionError("unreadable plugin directory"))

        with patch.object(ci.os, "walk", side_effect=walk):
            with self.assertRaises(PermissionError):
                ci.discover(self.root)

    def test_lower_severities_remain_visible_and_interpreters_are_not_overridden(self):
        self.env["SHELLCHECK_OPTS"] = "--shell=bash --exclude=SC2154"
        calls = self.run_analysis()
        for call in calls:
            self.assertEqual(call.kwargs["env"]["SHELLCHECK_OPTS"], "")
            self.assertFalse(any(arg.startswith("--shell=") for arg in call.args[0]))
        for call in calls[1:]:
            self.assertIn("--norc", call.args[0])
            for path in ci.discover(self.root):
                self.assertIn(path, call.args[0])
        self.assertIn("--severity=error", calls[-1].args[0])
        self.assertTrue(calls[-1].kwargs["check"])
        report = self.root / "reports/shellcheck"
        self.assertEqual(json.loads((report / "findings.json").read_text())["comments"], [self.finding])
        summary = json.loads((report / "summary.json").read_text())
        self.assertEqual(summary["counts_by_severity"], {"error": 0, "warning": 1, "info": 0, "style": 0})
        self.assertEqual(summary["counts_by_rule"], {"SC2154": 1})
        self.assertEqual(summary["file_count"], 5)
        self.assertIn("| warning | 1 |", (self.root / "step-summary").read_text())

    def test_clean_analysis_succeeds(self):
        self.run_analysis(comments=[])

    def test_blocking_findings_fail_after_preserving_evidence(self):
        self.finding.update(level="error", code=1035)
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_analysis(failure=1)
        summary = json.loads((self.root / "reports/shellcheck/summary.json").read_text())
        self.assertEqual(summary["counts_by_severity"]["error"], 1)

    def test_execution_and_usage_failures_are_not_informational_successes(self):
        for status in (2, 3, 4, 126, 127, -9):
            with self.subTest(status=status):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.run_analysis(status=status)
                self.assertFalse((self.root / "reports/shellcheck/summary.json").exists())
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_analysis(comments=[], failure=2)

    def test_invalid_reports_fail(self):
        for output in ("", "not json", "{}", '{"comments": null}'):
            with self.subTest(output=output):
                with self.assertRaises((KeyError, ValueError)):
                    self.run_analysis(output=output)
        with self.assertRaisesRegex(ValueError, "inconsistent exit status"):
            self.run_analysis(status=0)

    def archive(self, version=ci.VERSION):
        archive = self.root / "fixture.tar.xz"
        binary = f"#!/bin/sh\nprintf 'version: {version}\\n'\n".encode()
        with tarfile.open(archive, "w:xz") as file:
            entry = tarfile.TarInfo(f"shellcheck-v{ci.VERSION}/shellcheck")
            entry.size = len(binary)
            entry.mode = 0o755
            file.addfile(entry, io.BytesIO(binary))
        return archive.read_bytes()

    def install_archive(self, archive, checksum=None):
        run = subprocess.run

        def execute(command, **kwargs):
            if command[0] == "curl":
                Path(command[-1]).write_bytes(archive)
                return subprocess.CompletedProcess(command, 0)
            return run(command, **kwargs)

        with patch.object(ci, "SHA256", checksum or hashlib.sha256(archive).hexdigest()):
            with patch.object(ci.subprocess, "run", side_effect=execute) as calls:
                with redirect_stdout(io.StringIO()):
                    ci.install(self.env)
        return calls.call_args_list

    def test_verified_installation_exports_binary_only_after_version_check(self):
        calls = self.install_archive(self.archive())
        self.assertEqual([call.args[0][0] for call in calls[:2]], ["curl", "tar"])
        self.assertIn(f"/v{ci.VERSION}/shellcheck-v{ci.VERSION}.linux.x86_64.tar.xz", calls[0].args[0][-3])
        binary = self.root / f"agent-shellcheck/shellcheck-v{ci.VERSION}/shellcheck"
        self.assertEqual((self.root / "env").read_text(), f"SHELLCHECK={binary}\n")

    def test_checksum_mismatch_fails_before_extraction_or_execution(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.install_archive(self.archive(), checksum="0" * 64)
        self.assertFalse((self.root / f"agent-shellcheck/shellcheck-v{ci.VERSION}").exists())
        self.assertFalse((self.root / "env").exists())

    def test_wrong_installed_version_fails(self):
        with self.assertRaisesRegex(ValueError, "must report version"):
            self.install_archive(self.archive(version="0.10.0"))
        self.assertFalse((self.root / "env").exists())

    def test_download_and_extraction_failures_propagate(self):
        with patch.object(ci.subprocess, "run", side_effect=subprocess.CalledProcessError(22, "curl")):
            with self.assertRaises(subprocess.CalledProcessError):
                ci.install(self.env)
        with self.assertRaises(subprocess.CalledProcessError):
            self.install_archive(b"not an archive")
        self.assertFalse((self.root / "env").exists())


if __name__ == "__main__":
    unittest.main()
