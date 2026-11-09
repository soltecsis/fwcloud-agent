"""Validate SCA fail-closed evidence and mandatory package gates."""

import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("trivy_ci", Path(__file__).with_name("trivy-ci.py"))
trivy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trivy)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.report = {"SchemaVersion": 2, "Trivy": {"Version": trivy.VERSION}, "Results": [
            {"Type": "cargo", "Packages": [{"Name": "example", "Version": "1.0"}]}]}
        self.sbom = {"bomFormat": "CycloneDX", "components": [
            {"name": "example", "version": "1.0", "purl": "pkg:cargo/example@1.0"}]}

    def test_clean_inventory(self):
        self.assertEqual(trivy.validate(self.report, self.sbom), {})

    def test_all_findings_including_unfixed_are_counted(self):
        self.report["Results"][0]["Vulnerabilities"] = [
            {"Severity": severity, "FixedVersion": ""} for severity in ["HIGH", "CRITICAL", "UNKNOWN", "LOW", "MEDIUM"]]
        counts = trivy.validate(self.report, self.sbom)
        self.assertEqual(counts, dict.fromkeys(["HIGH", "CRITICAL", "UNKNOWN", "LOW", "MEDIUM"], 1))

    def test_missing_or_incomplete_inventory_is_rejected(self):
        for report in ({}, {**self.report, "Results": []}, {**self.report, "Trivy": {"Version": "wrong"}}):
            with self.subTest(report=report), self.assertRaises(ValueError):
                trivy.validate(report, self.sbom)
        for change in ({"components": []}, {"bomFormat": "wrong"}, {"components": [
            {"name": "example", "version": "2.0", "purl": "pkg:cargo/example@2.0"}]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                trivy.validate(self.report, {**self.sbom, **change})

    def test_unknown_severity_encoding_fails(self):
        report = copy.deepcopy(self.report)
        report["Results"][0]["Vulnerabilities"] = [{"Severity": "high"}]
        with self.assertRaises(ValueError):
            trivy.validate(report, self.sbom)

    def test_workflow_sca_is_mandatory_and_evidence_survives_failures(self):
        workflow = (Path(__file__).parents[1] / "workflows/main.yml").read_text()
        sca = workflow.split("\n  sca:\n")[1].split("\n  agent-ci:\n")[0]
        self.assertIn("ref: ${{ env.ANALYSIS_COMMIT }}", sca)
        self.assertIn("persist-credentials: false", sca)
        self.assertIn("trivy-ci.py install", sca)
        self.assertIn("trivy-ci.py scan", sca)
        self.assertIn("if: ${{ always() }}", sca)
        self.assertIn("if-no-files-found: error", sca)
        self.assertNotIn("continue-on-error", sca)
        self.assertNotIn("secrets.", sca)

    def scan_fixture(self, directory, findings=None, fail=False, missing=False):
        root = Path(directory)
        (root / "Cargo.toml").write_text("[package]\nname = 'example'\nversion = '1.0'\n")
        (root / "Cargo.lock").write_text("version = 4\n")
        db = root / "agent-trivy-cache/db"
        db.mkdir(parents=True)
        (db / "metadata.json").write_text(json.dumps(dict.fromkeys(
            ["Version", "UpdatedAt", "NextUpdate", "DownloadedAt"], "fixture")))
        report = copy.deepcopy(self.report)
        report["Results"][0]["Vulnerabilities"] = findings or []
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            if command[0] == "git":
                return subprocess.CompletedProcess(command, 0)
            self.assertNotIn("TRIVY_SKIP_DB_UPDATE", kwargs["env"])
            self.assertNotIn("--ignore-unfixed", command)
            if fail:
                raise subprocess.CalledProcessError(1, command)
            if not missing:
                output = Path(command[command.index("--output") + 1])
                output.write_text(json.dumps(self.sbom if "convert" in command else report))
            return subprocess.CompletedProcess(command, 0)

        def check_output(command, **kwargs):
            return "a" * 40 if command[0] == "git" else json.dumps({"Version": trivy.VERSION}).encode()

        env = {"RUNNER_TEMP": directory, "ANALYSIS_COMMIT": "a" * 40,
               "TRIVY_BINARY": "trivy", "TRIVY_SKIP_DB_UPDATE": "true"}
        with patch.object(trivy, "ROOT", root), patch.dict(os.environ, env), \
                patch.object(trivy.subprocess, "run", side_effect=run), \
                patch.object(trivy.subprocess, "check_output", side_effect=check_output):
            result = trivy.scan()
        return result, json.loads((root / "reports/sca/metadata.json").read_text()), commands

    def test_scan_blocks_high_and_critical_even_without_a_fix(self):
        for severity in ("HIGH", "CRITICAL"):
            with self.subTest(severity=severity), tempfile.TemporaryDirectory() as directory:
                result, metadata, commands = self.scan_fixture(directory, [{"Severity": severity}])
                self.assertEqual(result, 1)
                self.assertEqual(metadata["status"], "findings")
                self.assertEqual(len(metadata["reports"]), 2)
                self.assertTrue(any("convert" in command for command in commands))

    def test_clean_scan_binds_inputs_reports_and_database(self):
        with tempfile.TemporaryDirectory() as directory:
            result, metadata, _ = self.scan_fixture(directory)
            self.assertEqual(result, 0)
            self.assertEqual(metadata["status"], "success")
            self.assertEqual(set(metadata["inputs"]), {"Cargo.toml", "Cargo.lock"})
            self.assertEqual(len(metadata["databaseMetadataSha256"]), 64)

    def test_tool_failure_or_missing_report_cannot_succeed(self):
        for options in ({"fail": True}, {"missing": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises((subprocess.CalledProcessError, FileNotFoundError)):
                    self.scan_fixture(directory, **options)
                metadata = json.loads((Path(directory) / "reports/sca/metadata.json").read_text())
                self.assertEqual(metadata["status"], "error")

    def test_install_rejects_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.dict(os.environ, {"RUNNER_TEMP": directory}), \
                patch.object(trivy.urllib.request, "urlopen", return_value=io.BytesIO(b"corrupt")):
            with self.assertRaisesRegex(ValueError, "checksum"):
                trivy.install()
            self.assertFalse((Path(directory) / "agent-trivy/trivy").exists())


if __name__ == "__main__":
    unittest.main()
