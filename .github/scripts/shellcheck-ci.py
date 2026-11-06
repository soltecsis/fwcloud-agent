#!/usr/bin/env python3
"""Install verified ShellCheck and report the complete scope before enforcing errors."""

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.11.0"
SHA256 = "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
BLOCKING_SEVERITY = "error"
SEVERITIES = ("error", "warning", "info", "style")
MAINTAINER_SCRIPTS = ("preinst", "postinst", "prerm", "postrm")


def verify_version(binary, env):
    result = subprocess.run(
        [str(binary), "--version"], env=env, check=True, text=True, capture_output=True,
    )
    if f"version: {VERSION}" not in result.stdout.splitlines():
        raise ValueError(f"ShellCheck must report version {VERSION}")
    print(result.stdout, end="", flush=True)


def install(env):
    destination = Path(env["RUNNER_TEMP"]) / "agent-shellcheck"
    destination.mkdir(parents=True, exist_ok=True)
    archive_name = f"shellcheck-v{VERSION}.linux.x86_64.tar.xz"
    url = f"https://github.com/koalaman/shellcheck/releases/download/v{VERSION}/{archive_name}"
    with tempfile.TemporaryDirectory(prefix="download-", dir=destination) as temporary:
        archive = Path(temporary) / archive_name
        subprocess.run(
            ["curl", "--fail", "--silent", "--show-error", "--location",
             "--connect-timeout", "15", "--max-time", "120", url, "--output", str(archive)],
            env=env, check=True,
        )
        if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
            raise ValueError("ShellCheck archive SHA-256 mismatch; refusing to extract")
        print(f"{archive_name}: SHA-256 verified ({SHA256})", flush=True)
        subprocess.run(["tar", "-xJf", str(archive), "-C", str(destination)], env=env, check=True)
    binary = destination / f"shellcheck-v{VERSION}" / "shellcheck"
    verify_version(binary, env)
    with Path(env["GITHUB_ENV"]).open("a", encoding="utf-8") as file:
        file.write(f"SHELLCHECK={binary}\n")


def discover(root):
    plugins = root / "plugins"
    if not plugins.is_dir():
        raise ValueError("Missing plugins directory")

    def traversal_error(error):
        raise error

    files = []
    for directory, _, names in os.walk(plugins, onerror=traversal_error):
        for name in names:
            path = Path(directory) / name
            if name.endswith(".sh"):
                if not path.is_file():
                    raise ValueError(f"Invalid plugin script: {path}")
                files.append(path.relative_to(root).as_posix())
    if not files:
        raise ValueError("No plugin shell scripts found")
    for name in MAINTAINER_SCRIPTS:
        path = Path(".deb/maintainer-scripts") / name
        if not (root / path).is_file():
            raise ValueError(f"Missing Debian maintenance script: {path}")
        files.append(path.as_posix())
    return sorted(files)


def analyze(binary, env, root=ROOT):
    # Ambient configuration must not change interpreters, hide rules or lower policy.
    env = {**env, "SHELLCHECK_OPTS": ""}
    verify_version(binary, env)
    files = discover(root)
    print(f"Analyzing {len(files)} shell scripts; blocking severity: {BLOCKING_SEVERITY}", flush=True)
    command = [str(binary), "--norc", "--severity=style", "--format=json1", *files]
    result = subprocess.run(command, cwd=root, env=env, text=True, capture_output=True)
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="", flush=True)
    # Only code 1 means completed analysis with findings. Codes 2+ and signals fail.
    if result.returncode not in (0, 1):
        raise subprocess.CalledProcessError(result.returncode, command)
    findings = json.loads(result.stdout)
    comments = findings["comments"]
    if not isinstance(comments, list) or result.returncode != int(bool(comments)):
        raise ValueError("Invalid ShellCheck findings or inconsistent exit status")
    counts = dict.fromkeys(SEVERITIES, 0)
    rules = Counter()
    for comment in comments:
        counts[comment["level"]] += 1
        rules[f"SC{comment['code']}"] += 1
        print(f"{comment['file']}:{comment['line']}:{comment['column']}: "
              f"{comment['level']}: {comment['message']} [SC{comment['code']}]")

    report = root / "reports/shellcheck"
    report.mkdir(parents=True, exist_ok=True)
    (report / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    summary = {
        "shellcheck_version": VERSION,
        "archive_sha256": SHA256,
        "blocking_severity": BLOCKING_SEVERITY,
        "source_commit": env.get("ANALYSIS_COMMIT"),
        "run_id": env.get("GITHUB_RUN_ID"),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
        "file_count": len(files),
        "files": files,
        "counts_by_severity": counts,
        "counts_by_rule": dict(sorted(rules.items())),
    }
    (report / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    markdown = (
        f"### ShellCheck {VERSION}\n\n"
        f"Analyzed files: {len(files)}. Blocking severity: `{BLOCKING_SEVERITY}`.\n\n"
        "| Severity | Findings |\n| --- | --- |\n"
        + "".join(f"| {level} | {counts[level]} |\n" for level in SEVERITIES)
        + "\n| Rule | Findings |\n| --- | --- |\n"
        + "".join(f"| {rule} | {count} |\n" for rule, count in sorted(rules.items()))
        + "\nAll findings and the file inventory are retained in the ShellCheck artifact.\n"
    )
    (report / "summary.md").write_text(markdown, encoding="utf-8")
    print(markdown, flush=True)
    if env.get("GITHUB_STEP_SUMMARY"):
        with Path(env["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as file:
            file.write(markdown)

    # Keep the required policy explicit and independent of informational findings.
    subprocess.run(
        [str(binary), "--norc", f"--severity={BLOCKING_SEVERITY}", "--format=gcc", *files],
        cwd=root, env=env, check=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("install", "analyze"))
    args = parser.parse_args()
    try:
        if args.command == "install":
            install(os.environ)
        else:
            analyze(os.environ["SHELLCHECK"], os.environ)
    except (OSError, KeyError, TypeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ShellCheck CI failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
