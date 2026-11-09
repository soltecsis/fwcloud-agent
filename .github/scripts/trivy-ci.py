"""Pinned Cargo vulnerability scan and CycloneDX inventory (not a binary SBOM)."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid


VERSION = "0.76.2"
SHA256 = "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"
URL = f"https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_Linux-64bit.tar.gz"
ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


EVIDENCE = ("trivy.json", "sbom.cdx.json", "metadata.json", "install.log",
            "scan.log", "sbom.log", "blocking.txt")


def publish_log(name, text):
    print(f"--- Trivy {name} ---", flush=True)
    # Scanner output is diagnostic data, never GitHub workflow commands.
    token = uuid.uuid4().hex
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::stop-commands::{token}", flush=True)
    print(text, end="" if text.endswith("\n") else "\n", flush=True)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{token}::", flush=True)


def install():
    output = ROOT / "reports/sca"
    output.mkdir(parents=True, exist_ok=True)
    for name in EVIDENCE:
        (output / name).unlink(missing_ok=True)
    text = f"Installing checksum-pinned Trivy {VERSION}.\n"
    try:
        install_binary()
        text += f"Archive SHA-256 verified: {SHA256}\nInstalled CLI version verified: {VERSION}\n"
    except Exception:
        text += "Installation failed during download, archive verification, extraction or CLI verification.\n"
        raise
    finally:
        (output / "install.log").write_text(text)
        publish_log("installation", text)


def install_binary():
    directory = Path(os.environ["RUNNER_TEMP"]) / "agent-trivy"
    directory.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=120) as response:
        archive = response.read()
    if hashlib.sha256(archive).hexdigest() != SHA256:
        raise ValueError("Trivy archive checksum mismatch")
    with tempfile.TemporaryFile() as stream:
        stream.write(archive)
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:gz") as tar:
            member = tar.getmember("trivy")
            if not member.isfile():
                raise ValueError("Invalid Trivy executable")
            binary = directory / "trivy"
            binary.write_bytes(tar.extractfile(member).read())
    binary.chmod(0o700)
    version = json.loads(subprocess.check_output([str(binary), "--version", "--format", "json"]))
    if version["Version"] != VERSION:
        raise ValueError("Unexpected Trivy version")
    with open(os.environ["GITHUB_ENV"], "a") as output:
        output.write(f"TRIVY_BINARY={binary}\n")


def validate(report, sbom):
    if report.get("SchemaVersion") != 2:
        raise ValueError("Unsupported vulnerability report")
    if report.get("Trivy", {}).get("Version") != VERSION:
        raise ValueError("Unexpected report producer")
    results = report.get("Results", [])
    cargo = [item for item in results if item.get("Type") == "cargo"]
    if not cargo or not any(item.get("Packages") for item in cargo):
        raise ValueError("Missing Cargo dependency inventory")
    if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
        raise ValueError("Missing CycloneDX inventory")
    packages = {(p["Name"], p["Version"]) for item in cargo for p in item["Packages"]}
    components = {(p["name"], p["version"]) for p in sbom["components"] if p.get("purl", "").startswith("pkg:cargo/")}
    if not packages <= components:
        raise ValueError("Incomplete CycloneDX Cargo inventory")
    counts = {}
    for item in cargo:
        for finding in item.get("Vulnerabilities") or []:
            severity = finding.get("Severity", "UNKNOWN")
            if severity not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("Invalid vulnerability severity")
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def run_stage(command, directory, env, output, name, filename, metadata):
    """Retain and display native diagnostics, including partial timeout output."""
    state = {"status": "error", "exitCode": None}
    metadata["stages"][name] = state
    text = ""
    try:
        result = subprocess.run(command, cwd=directory, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        text = result.stdout or ""
        state["exitCode"] = result.returncode
        if result.returncode:
            raise ValueError("Trivy stage failed")
        state["status"] = "success"
    except subprocess.TimeoutExpired as error:
        partial = error.stdout or b""
        text = partial.decode("utf-8", errors="replace") if isinstance(partial, bytes) else partial
        text += "\nTrivy stage timed out.\n"
        raise
    except OSError:
        text = "Unable to execute Trivy.\n"
        raise
    finally:
        (output / filename).write_text(text)
        publish_log(name, text)


def summary_text(metadata):
    stages = metadata["stages"]
    counts = metadata.get("severityCounts")
    text = (f"## Agent Cargo SCA\n\nStatus: **{metadata['status']}**\n\n"
            f"Analyzed commit: `{metadata.get('sourceCommit', 'unavailable')}`\n\n"
            f"Configured Trivy: {VERSION}; verified CLI: {metadata.get('installedVersion', 'unavailable')}\n\n"
            f"Database updated: {metadata.get('database', {}).get('UpdatedAt', 'unavailable')}\n\n"
            f"Packages: {metadata.get('packageCount', 'unavailable')}; "
            f"blocking findings (HIGH/CRITICAL): {metadata.get('blockingFindingCount', 'unavailable')}\n\n"
            "| Severity | Findings |\n| --- | --- |\n")
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        text += f"| {severity} | {counts.get(severity, 0) if counts is not None else 'unavailable'} |\n"
    text += "\n| Stage | Result | Native exit code |\n| --- | --- | --- |\n"
    for name, state in stages.items():
        text += f"| {name} | {state['status']} | {state.get('exitCode', '—')} |\n"
    if metadata.get("errorStage"):
        text += f"\nIncomplete analysis at **{metadata['errorStage']}**; this is not a clean scan.\n"
    return text + ("\nDetailed results: job logs and the `agent-sca` artifact "
                   "(`install.log`, `scan.log`, `sbom.log`, `blocking.txt` when available).\n")


def scan():
    output = ROOT / "reports/sca"
    output.mkdir(parents=True, exist_ok=True)
    for name in EVIDENCE:
        if name == "install.log":
            continue
        (output / name).unlink(missing_ok=True)
    metadata = {"status": "error", "scannerVersion": VERSION,
                "scannerArchiveSha256": SHA256,
                "scope": "Cargo source dependencies; not compiled binary or host inventory",
                "repository": os.environ.get("GITHUB_REPOSITORY"),
                "runId": os.environ.get("GITHUB_RUN_ID"),
                "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "stages": {name: {"status": "not-run"} for name in
                           ("installation", "preparation", "scan", "sbom", "blocking-table", "validation")}}
    stage = "installation"
    try:
        installed = os.environ.get("INSTALL_RESULT", "success")
        metadata["stages"][stage]["status"] = installed if installed == "success" else "error"
        if installed != "success":
            raise ValueError("Installation did not succeed")
        stage = "preparation"
        metadata["stages"][stage]["status"] = "error"
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        if head != os.environ["ANALYSIS_COMMIT"]:
            raise ValueError("Analysis revision mismatch")
        metadata["sourceCommit"] = head
        metadata["inputs"] = {}
        env = {k: v for k, v in os.environ.items() if not k.startswith("TRIVY_")}
        binary = os.environ["TRIVY_BINARY"]
        version = json.loads(subprocess.check_output([binary, "--version", "--format", "json"], env=env))
        if version["Version"] != VERSION:
            raise ValueError("Unexpected Trivy version")
        metadata["installedVersion"] = version["Version"]
        with tempfile.TemporaryDirectory(prefix="agent-sca-", dir=os.environ["RUNNER_TEMP"]) as temporary:
            directory = Path(temporary)
            for name in ("Cargo.toml", "Cargo.lock"):
                source = ROOT / name
                if source.is_symlink() or not source.is_file():
                    raise ValueError("Invalid Cargo input")
                subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", name], cwd=ROOT, check=True, capture_output=True)
                metadata["inputs"][name] = digest(source)
                shutil.copyfile(source, directory / name)
            config = directory / "config.yaml"
            config.write_text("{}\n")
            ignore = directory / "ignore"
            ignore.write_text("")
            common = [binary, "--config", str(config), "--cache-dir", str(Path(os.environ["RUNNER_TEMP"]) / "agent-trivy-cache")]
            commands = [
                ("scan", "scan.log", common + ["fs", "--scanners", "vuln", "--pkg-types", "library", "--list-all-pkgs", "--no-progress", "--ignore-unfixed=false", "--exit-code", "0", "--ignorefile", str(ignore), "--format", "json", "--output", str(output / "trivy.json"), str(directory)]),
                ("sbom", "sbom.log", common + ["convert", "--format", "cyclonedx", "--output", str(output / "sbom.cdx.json"), str(output / "trivy.json")]),
                ("blocking-table", "blocking.txt", common + ["convert", "--format", "table", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", "--exit-code", "0", str(output / "trivy.json")]),
            ]
            metadata["stages"]["preparation"]["status"] = "success"
            for stage, filename, command in commands:
                run_stage(command, directory, env, output, stage, filename, metadata)
        stage = "validation"
        metadata["stages"][stage]["status"] = "error"
        report = json.loads((output / "trivy.json").read_text())
        sbom = json.loads((output / "sbom.cdx.json").read_text())
        counts = validate(report, sbom)
        database = Path(os.environ["RUNNER_TEMP"]) / "agent-trivy-cache/db/metadata.json"
        db = json.loads(database.read_text())
        if not all(db.get(key) for key in ("Version", "UpdatedAt", "NextUpdate", "DownloadedAt")):
            raise ValueError("Missing vulnerability database identity")
        blocked = counts.get("HIGH", 0) + counts.get("CRITICAL", 0)
        metadata.update(status="findings" if blocked else "success", severityCounts=counts,
                        blockingFindingCount=blocked,
                        database=db, databaseMetadataSha256=digest(database),
                        packageCount=sum(len(item["Packages"]) for item in report["Results"] if item.get("Type") == "cargo"),
                        reports={name: digest(output / name) for name in EVIDENCE
                                 if name != "metadata.json" and (output / name).is_file()})
        metadata["stages"][stage]["status"] = "success"
        return 1 if blocked else 0
    except Exception:
        metadata["errorStage"] = stage
        raise
    finally:
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        text = summary_text(metadata)
        print(text, flush=True)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                summary.write(text)


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["install"]:
            install()
        elif sys.argv[1:] == ["scan"]:
            sys.exit(scan())
        else:
            sys.exit("Expected install or scan")
    except Exception:
        sys.exit("Trivy control failed; no successful scan is claimed.")
