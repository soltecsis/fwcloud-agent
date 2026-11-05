#!/usr/bin/env python3
"""Install pinned Rust inputs and record only allowlisted CI provenance."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
TOOL_COMMANDS = {
    "cargo-audit": ["cargo-audit", "--version"],
    "cargo-tarpaulin": ["cargo-tarpaulin", "--version"],
    "cargo-deb": ["cargo-deb", "--version"],
    # cargo-rpm 0.8 has a version subcommand instead of --version.
    "cargo-rpm": ["cargo", "rpm", "version"],
}


def read_pins(root=ROOT):
    with (root / "rust-toolchain.toml").open("rb") as file:
        toolchain = tomllib.load(file)["toolchain"]
    channel = toolchain.get("channel", "")
    if not isinstance(channel, str) or not VERSION.fullmatch(channel):
        raise ValueError("Rust must use an exact release version")
    if toolchain.get("profile") != "minimal":
        raise ValueError("Rust must use the minimal profile")
    if toolchain.get("components") != ["rustfmt", "clippy"]:
        raise ValueError("Rust must include the pinned rustfmt and clippy components")
    with (root / ".github/ci-tools.toml").open("rb") as file:
        tools = tomllib.load(file)["tools"]
    if set(tools) != set(TOOL_COMMANDS):
        raise ValueError("Unexpected Cargo utility configuration")
    if any(not isinstance(value, str) or not VERSION.fullmatch(value) for value in tools.values()):
        raise ValueError("Cargo utilities must use exact release versions")
    return toolchain, tools


def output(command, *, env, root=ROOT):
    result = subprocess.run(
        command, cwd=root, env=env, check=True, text=True, capture_output=True
    )
    return result.stdout.strip()


def verify_release(name, actual, expected):
    if name == "rustc":
        match = re.search(r"^release: ([^\s]+)$", actual, re.MULTILINE)
    else:
        match = re.match(rf"{re.escape(name)} ([^\s]+)(?:\s|$)", actual)
    if not match or match.group(1) != expected:
        raise ValueError(f"Installed {name} does not match its configured release")
    return actual


def required_context(env):
    names = (
        "SOURCE_COMMIT", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
        "GITHUB_WORKFLOW", "GITHUB_EVENT_NAME", "GITHUB_REF", "GITHUB_JOB",
    )
    for name in names:
        if not env.get(name):
            raise ValueError(f"Missing CI context: {name}")
    if not re.fullmatch(r"[0-9a-f]{40}", env["SOURCE_COMMIT"]):
        raise ValueError("Invalid source commit")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", env["GITHUB_REPOSITORY"], re.ASCII):
        raise ValueError("Invalid repository")
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]*", env[name]):
            raise ValueError(f"Invalid CI context: {name}")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", env["GITHUB_JOB"]):
        raise ValueError("Invalid job identifier")


def record(env, tool="", root=ROOT):
    required_context(env)
    toolchain, tools = read_pins(root)
    if tool and tool not in tools:
        raise ValueError("Unsupported Cargo utility")
    head = output(["git", "rev-parse", "HEAD"], env=env, root=root)
    if head != env["SOURCE_COMMIT"]:
        raise ValueError("Checked-out revision differs from SOURCE_COMMIT")
    versions = {
        "rustc": verify_release(
            "rustc", output(["rustc", "--version", "--verbose"], env=env, root=root),
            toolchain["channel"],
        ),
        "cargo": verify_release(
            "cargo", output(["cargo", "--version", "--verbose"], env=env, root=root),
            toolchain["channel"],
        ),
        "rustfmt": output(["cargo", "fmt", "--version"], env=env, root=root),
        "clippy": output(["cargo", "clippy", "--version"], env=env, root=root),
    }
    # Component version numbers differ from rustc; verify the release's commit.
    commit = re.search(r"^commit-hash: ([0-9a-f]{40})$", versions["rustc"], re.MULTILINE)
    if not commit:
        raise ValueError("Rust compiler provenance is missing")
    for component in ("rustfmt", "clippy"):
        component_commit = re.fullmatch(
            rf"{component} [^\s]+ \(([0-9a-f]{{9,40}}) [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}\)",
            versions[component],
        )
        if not component_commit or not commit.group(1).startswith(component_commit.group(1)):
            raise ValueError(f"Installed {component} differs from the Rust release")
    if tool:
        versions[tool] = verify_release(
            "tarpaulin" if tool == "cargo-tarpaulin" else tool,
            output(TOOL_COMMANDS[tool], env=env, root=root), tools[tool],
        )
    metadata = {
        "schema_version": 1,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "source_commit": head,
        "repository": env["GITHUB_REPOSITORY"],
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env["GITHUB_RUN_ATTEMPT"],
        "workflow": env["GITHUB_WORKFLOW"],
        "event": env["GITHUB_EVENT_NAME"],
        "ref": env["GITHUB_REF"],
        "job": env["GITHUB_JOB"],
        "runner_os": env.get("RUNNER_OS", "unavailable"),
        "runner_arch": env.get("RUNNER_ARCH", "unavailable"),
        "runner_image_os": env.get("ImageOS", "unavailable"),
        "runner_image_version": env.get("ImageVersion", "unavailable"),
        "cargo_lock_sha256": hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest(),
        "configured": {"rust": toolchain, "tools": tools},
        "installed": versions,
    }
    destination = root / "reports/ci" / (env["GITHUB_JOB"] + ".json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    for name, value in versions.items():
        print(f"{name}: {value}")
    return metadata


def setup(env, root=ROOT):
    required_context(env)
    toolchain, tools = read_pins(root)
    tool = env.get("CI_CARGO_TOOL", "")
    if tool and tool not in tools:
        raise ValueError("Unsupported Cargo utility")
    for name in ("RUNNER_TEMP", "GITHUB_ENV", "GITHUB_PATH"):
        if not env.get(name):
            raise ValueError(f"Missing CI context: {name}")
    command = ["rustup", "toolchain", "install", toolchain["channel"],
               "--profile", "minimal", "--no-self-update"]
    for component in toolchain["components"]:
        command.extend(["--component", component])
    subprocess.run(command, cwd=root, env=env, check=True)
    env = dict(env, RUSTUP_TOOLCHAIN=toolchain["channel"])
    with Path(env["GITHUB_ENV"]).open("a", encoding="utf-8") as file:
        file.write(f"RUSTUP_TOOLCHAIN={toolchain['channel']}\n")
    if tool:
        install_root = Path(env["RUNNER_TEMP"]) / "agent-ci-tools"
        subprocess.run(
            ["cargo", "install", "--locked", "--version", "=" + tools[tool],
             "--registry", "crates-io", "--root", str(install_root), tool],
            cwd=root, env=env, check=True,
        )
        bin_dir = str(install_root / "bin")
        env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
        with Path(env["GITHUB_PATH"]).open("a", encoding="utf-8") as file:
            file.write(bin_dir + "\n")
    return record(env, tool, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("setup", "record"))
    args = parser.parse_args()
    try:
        if args.command == "setup":
            setup(os.environ)
        else:
            record(os.environ, os.environ.get("CI_CARGO_TOOL", ""))
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        # Avoid forwarding subprocess output or environment values into evidence.
        if isinstance(error, subprocess.CalledProcessError):
            print("Rust CI command failed; inspect the preceding installation log", file=sys.stderr)
        else:
            print(f"Rust CI error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
