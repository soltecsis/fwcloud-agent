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


VERSION = "0.76.2"
SHA256 = "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"
URL = f"https://github.com/aquasecurity/trivy/releases/download/v{VERSION}/trivy_{VERSION}_Linux-64bit.tar.gz"
ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def install():
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


def scan():
    output = ROOT / "reports/sca"
    output.mkdir(parents=True, exist_ok=True)
    for name in ("trivy.json", "sbom.cdx.json", "metadata.json"):
        (output / name).unlink(missing_ok=True)
    metadata = {"status": "error", "scannerVersion": VERSION,
                "scannerArchiveSha256": SHA256,
                "scope": "Cargo source dependencies; not compiled binary or host inventory",
                "repository": os.environ.get("GITHUB_REPOSITORY"),
                "runId": os.environ.get("GITHUB_RUN_ID"),
                "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT")}
    try:
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
                common + ["fs", "--scanners", "vuln", "--pkg-types", "library", "--list-all-pkgs", "--ignorefile", str(ignore), "--format", "json", "--output", str(output / "trivy.json"), str(directory)],
                common + ["convert", "--format", "cyclonedx", "--output", str(output / "sbom.cdx.json"), str(output / "trivy.json")],
            ]
            for command in commands:
                subprocess.run(command, cwd=directory, env=env, check=True, capture_output=True, timeout=600)
        report = json.loads((output / "trivy.json").read_text())
        sbom = json.loads((output / "sbom.cdx.json").read_text())
        counts = validate(report, sbom)
        database = Path(os.environ["RUNNER_TEMP"]) / "agent-trivy-cache/db/metadata.json"
        db = json.loads(database.read_text())
        if not all(db.get(key) for key in ("Version", "UpdatedAt", "NextUpdate", "DownloadedAt")):
            raise ValueError("Missing vulnerability database identity")
        blocked = counts.get("HIGH", 0) + counts.get("CRITICAL", 0)
        metadata.update(status="findings" if blocked else "success", severityCounts=counts,
                        database=db, databaseMetadataSha256=digest(database),
                        packageCount=sum(len(item["Packages"]) for item in report["Results"] if item.get("Type") == "cargo"),
                        reports={name: digest(output / name) for name in ("trivy.json", "sbom.cdx.json")})
        return 1 if blocked else 0
    finally:
        (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                summary.write(f"## Agent Cargo SCA\n\nStatus: {metadata['status']}\n\nSeverity counts: {json.dumps(metadata.get('severityCounts', {}))}\n")


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
