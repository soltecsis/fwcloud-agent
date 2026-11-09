"""Validate SCA fail-closed evidence and mandatory package gates."""

import copy
from contextlib import redirect_stdout
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
        self.assertIn("INSTALL_RESULT: ${{ steps.install_trivy.outcome }}", sca)
        scan_step = sca.split("      - name: Scan Cargo dependencies and generate CycloneDX", 1)[1].split("      - name:", 1)[0]
        self.assertIn("if: ${{ always() }}", scan_step)
        self.assertIn("if: ${{ always() }}", sca)
        self.assertIn("if-no-files-found: error", sca)
        self.assertNotIn("continue-on-error", sca)
        self.assertNotIn("secrets.", sca)

    def scan_fixture(self, directory, findings=None, fail=False, missing=False,
                     failed_stage="scan", install_result="success", timeout=False):
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
        evidence = root / "reports/sca"
        evidence.mkdir(parents=True)
        (evidence / "install.log").write_text("Synthetic installation receipt\n")

        def run(command, **kwargs):
            commands.append(command)
            if command[0] == "git":
                return subprocess.CompletedProcess(command, 0)
            self.assertNotIn("TRIVY_SKIP_DB_UPDATE", kwargs["env"])
            self.assertNotIn("--ignore-unfixed", command)
            stage = "scan" if "fs" in command else "sbom" if "cyclonedx" in command else "blocking-table"
            diagnostics = f"Synthetic {stage} diagnostics\n"
            if stage == failed_stage and timeout:
                raise subprocess.TimeoutExpired(command, 600, output=diagnostics.encode())
            if stage == failed_stage and fail:
                return subprocess.CompletedProcess(command, 2, stdout=diagnostics)
            if not missing and "--output" in command:
                output = Path(command[command.index("--output") + 1])
                output.write_text(json.dumps(self.sbom if "convert" in command else report))
            return subprocess.CompletedProcess(command, 0, stdout=diagnostics)

        def check_output(command, **kwargs):
            return "a" * 40 if command[0] == "git" else json.dumps({"Version": trivy.VERSION}).encode()

        env = {"RUNNER_TEMP": directory, "ANALYSIS_COMMIT": "a" * 40,
               "TRIVY_BINARY": "trivy", "TRIVY_SKIP_DB_UPDATE": "true",
               "INSTALL_RESULT": install_result, "GITHUB_STEP_SUMMARY": str(root / "summary.md")}
        console = io.StringIO()
        with patch.object(trivy, "ROOT", root), patch.dict(os.environ, env), \
                patch.object(trivy.subprocess, "run", side_effect=run), \
                patch.object(trivy.subprocess, "check_output", side_effect=check_output), \
                redirect_stdout(console):
            result = trivy.scan()
        for name in ("scan", "sbom", "blocking-table"):
            self.assertIn(f"Synthetic {name} diagnostics", console.getvalue())
        return result, json.loads((root / "reports/sca/metadata.json").read_text()), commands

    def test_scan_blocks_high_and_critical_even_without_a_fix(self):
        for severity in ("HIGH", "CRITICAL"):
            with self.subTest(severity=severity), tempfile.TemporaryDirectory() as directory:
                result, metadata, commands = self.scan_fixture(directory, [{"Severity": severity}])
                self.assertEqual(result, 1)
                self.assertEqual(metadata["status"], "findings")
                self.assertEqual(set(metadata["reports"]), set(trivy.EVIDENCE) - {"metadata.json"})
                self.assertEqual(metadata["blockingFindingCount"], 1)
                self.assertTrue(any("convert" in command for command in commands))
                table = next(command for command in commands if "table" in command)
                self.assertNotIn("--output", table)
                self.assertEqual(table[table.index("--severity") + 1], "HIGH,CRITICAL")

    def test_clean_scan_binds_inputs_reports_and_database(self):
        with tempfile.TemporaryDirectory() as directory:
            result, metadata, _ = self.scan_fixture(directory)
            self.assertEqual(result, 0)
            self.assertEqual(metadata["status"], "success")
            self.assertEqual(set(metadata["inputs"]), {"Cargo.toml", "Cargo.lock"})
            self.assertEqual(len(metadata["databaseMetadataSha256"]), 64)
            self.assertTrue(all(state["status"] == "success" for state in metadata["stages"].values()))
            for name, checksum in metadata["reports"].items():
                self.assertEqual(checksum, trivy.digest(Path(directory) / "reports/sca" / name))
            summary = (Path(directory) / "summary.md").read_text()
            self.assertIn("Analyzed commit: `" + "a" * 40 + "`", summary)
            self.assertIn("verified CLI: " + trivy.VERSION, summary)
            self.assertIn("Packages: 1; blocking findings (HIGH/CRITICAL): 0", summary)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
                self.assertIn(f"| {severity} | 0 |", summary)
            for name in ("scan.log", "sbom.log", "blocking.txt"):
                self.assertIn("diagnostics", (Path(directory) / "reports/sca" / name).read_text())

    def test_tool_failure_or_missing_report_cannot_succeed(self):
        for options in ({"fail": True}, {"missing": True}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.scan_fixture(directory, **options)
                metadata = json.loads((Path(directory) / "reports/sca/metadata.json").read_text())
                self.assertEqual(metadata["status"], "error")
                self.assertEqual(metadata["errorStage"], "scan" if options.get("fail") else "validation")

    def test_each_native_failure_retains_diagnostics_and_identifies_stage(self):
        filenames = {"scan": "scan.log", "sbom": "sbom.log", "blocking-table": "blocking.txt"}
        for stage, filename in filenames.items():
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    self.scan_fixture(directory, fail=True, failed_stage=stage)
                root = Path(directory)
                metadata = json.loads((root / "reports/sca/metadata.json").read_text())
                self.assertEqual(metadata["status"], "error")
                self.assertEqual(metadata["errorStage"], stage)
                self.assertEqual(metadata["stages"][stage], {"status": "error", "exitCode": 2})
                self.assertEqual(metadata["stages"]["validation"]["status"], "not-run")
                self.assertIn(f"Synthetic {stage} diagnostics", (root / "reports/sca" / filename).read_text())
                summary = (root / "summary.md").read_text()
                self.assertIn(f"Incomplete analysis at **{stage}**", summary)
                self.assertIn("| HIGH | unavailable |", summary)

    def test_timeout_keeps_partial_diagnostics_and_failed_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(subprocess.TimeoutExpired):
                self.scan_fixture(directory, timeout=True)
            root = Path(directory)
            log = (root / "reports/sca/scan.log").read_text()
            self.assertIn("Synthetic scan diagnostics", log)
            self.assertIn("timed out", log)
            metadata = json.loads((root / "reports/sca/metadata.json").read_text())
            self.assertEqual(metadata["stages"]["scan"], {"status": "error", "exitCode": None})
            self.assertEqual(metadata["status"], "error")

    def test_install_failure_stops_scanning_and_produces_failed_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "Installation"):
                self.scan_fixture(directory, install_result="failure")
            root = Path(directory)
            metadata = json.loads((root / "reports/sca/metadata.json").read_text())
            self.assertEqual(metadata["errorStage"], "installation")
            self.assertEqual(metadata["stages"]["scan"]["status"], "not-run")
            self.assertTrue((root / "reports/sca/install.log").is_file())
            self.assertFalse((root / "reports/sca/scan.log").exists())
            self.assertIn("Incomplete analysis at **installation**", (root / "summary.md").read_text())

    def test_unavailable_executable_is_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            metadata = {"stages": {}}
            with patch.object(trivy.subprocess, "run", side_effect=FileNotFoundError), redirect_stdout(io.StringIO()):
                with self.assertRaises(FileNotFoundError):
                    trivy.run_stage(["missing"], directory, {}, Path(directory), "scan", "scan.log", metadata)
            self.assertIn("Unable to execute", (Path(directory) / "scan.log").read_text())
            self.assertEqual(metadata["stages"]["scan"]["status"], "error")

    def test_workflow_commands_in_native_output_are_not_executed(self):
        console = io.StringIO()
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}), redirect_stdout(console):
            trivy.publish_log("scan", "::error::diagnostic fixture\n")
        lines = console.getvalue().splitlines()
        token = lines[1].removeprefix("::stop-commands::")
        self.assertEqual(lines[2], "::error::diagnostic fixture")
        self.assertEqual(lines[3], f"::{token}::")

    def test_install_rejects_checksum_mismatch(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(trivy, "ROOT", Path(directory)), \
                patch.dict(os.environ, {"RUNNER_TEMP": directory}), \
                patch.object(trivy.urllib.request, "urlopen", return_value=io.BytesIO(b"corrupt")), \
                redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "checksum"):
                trivy.install()
            self.assertFalse((Path(directory) / "agent-trivy/trivy").exists())
            self.assertIn("Installation failed", (Path(directory) / "reports/sca/install.log").read_text())


if __name__ == "__main__":
    unittest.main()
