#!/usr/bin/env python3
"""Install checksum-pinned reporting binaries without compiling CI utilities."""

import hashlib
import io
import os
from pathlib import Path
import platform
import json
import subprocess
import tarfile
import time
import tomllib
import urllib.request


ROOT = Path(__file__).resolve().parents[2]


def binary(archive, expected_sha, name):
    if hashlib.sha256(archive).hexdigest() != expected_sha:
        raise ValueError("Reporting tool archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
        members = [m for m in package.getmembers() if m.name in (name, "./" + name)]
        if len(members) != 1 or not members[0].isfile():
            raise ValueError("Missing regular reporting tool binary")
        return package.extractfile(members[0]).read()


def install(env=os.environ, root=ROOT):
    started = time.monotonic()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Reporting binaries require a Linux x86_64 runner")
    pins = tomllib.loads((root / ".github/report-tools.toml").read_text())
    rust = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    destination = Path(env["RUNNER_TEMP"]) / "agent-report-tools/bin"
    destination.mkdir(parents=True, exist_ok=True)
    for name, pin in pins.items():
        if tuple(map(int, rust.split("."))) < tuple(map(int, pin["rust-version"].split("."))):
            raise ValueError("Reporting tool requires a newer Rust version")
        with urllib.request.urlopen(pin["url"], timeout=60) as response:
            contents = response.read()
        executable = destination / name
        executable.write_bytes(binary(contents, pin["sha256"], name))
        executable.chmod(0o755)
        args = [str(executable)]
        if name == "cargo-llvm-cov":
            args.append("llvm-cov")
        output = subprocess.check_output([*args, "--version"], text=True).strip()
        if output.split()[:2] != [name, pin["version"]]:
            raise ValueError("Installed reporting tool version mismatch")
        print(output)
    subprocess.run(["rustup", "component", "add", "--toolchain", rust,
                    "llvm-tools-preview"], check=True, env=env)
    with Path(env["GITHUB_PATH"]).open("a") as output:
        output.write(str(destination) + "\n")
    evidence = root / "reports/ci/report-tools.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(json.dumps({"installation_seconds": time.monotonic() - started,
                                    "tools": pins}, indent=2) + "\n")


if __name__ == "__main__":
    install()
