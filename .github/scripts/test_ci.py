#!/usr/bin/env python3
"""Build/list without executing tests, run Nextest once, then export its coverage."""

import argparse
from collections import Counter
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time

from ci_reports import ROOT, context, coverage, lcov, read_json, require, verify_identity, write_json


def instrumented_env(root, env):
    result = subprocess.check_output(["cargo", "llvm-cov", "show-env", "--sh"],
                                     cwd=root, env=env, text=True)
    result_env = dict(env)
    for line in result.splitlines():
        words = shlex.split(line)
        require(len(words) == 2 and words[0] == "export" and "=" in words[1], "Invalid LLVM environment")
        key, value = words[1].split("=", 1)
        result_env[key] = value
    return result_env


class Execution:
    def __init__(self, root=ROOT, env=os.environ, fresh=False):
        self.root = root
        # show-env uses target/ by default, while the nextest wrapper otherwise
        # uses target/llvm-cov-target. Keep both commands on the same build cache.
        self.env = dict(env, CARGO_LLVM_COV_TARGET_DIR=str(root / "target"))
        self.path = root / "reports/tests/execution.json"
        identity = context(root, env)
        if fresh:
            (root / "reports/metadata.json").unlink(missing_ok=True)
            for path in (root / "reports/tests", root / "reports/coverage", root / "target/nextest/ci"):
                if path.exists():
                    shutil.rmtree(path)
            for name in ("tests", "coverage"):
                (root / "reports" / name).mkdir(parents=True, exist_ok=True)
            self.data = identity | {"completed": False, "commands": {}, "timings_seconds": {}}
            installation = root / "reports/ci/report-tools.json"
            if installation.exists():
                self.data["timings_seconds"]["tool_installation"] = read_json(installation)["installation_seconds"]
            self.save()
        else:
            self.data = read_json(self.path)
            verify_identity(self.data, identity)

    def save(self):
        write_json(self.path, self.data)

    def command(self, name, args, env=None, capture=False):
        started = time.monotonic()
        try:
            result = subprocess.run(args, cwd=self.root, env=env or self.env,
                                    text=True, stdout=subprocess.PIPE if capture else None)
            code, output = result.returncode, result.stdout
        except OSError:
            code, output = 127, ""
        self.data["commands"][name] = {"exit_code": code}
        self.data["timings_seconds"][name] = time.monotonic() - started
        self.save()
        return code, output

    def build(self):
        code, _ = self.command("clean", ["cargo", "llvm-cov", "clean", "--workspace", "--locked"])
        if code:
            return code
        env = instrumented_env(self.root, self.env)
        code, _ = self.command("build", ["cargo", "nextest", "run", "--profile", "ci",
                                         "--locked", "--no-tests=fail", "--no-run"], env)
        if code:
            return code
        return self.discover(env)

    def discover(self, env):
        # Both runners list the same instrumented binaries. --list never executes test bodies.
        cargo_code, cargo = self.command("cargo_list", ["cargo", "test", "--locked", "--", "--list"], env, True)
        nextest_code, nextest = self.command("nextest_list", ["cargo", "nextest", "list", "--profile", "ci",
                                                            "--locked", "--message-format", "json"], env, True)
        doc_code, docs = self.command("doctest_list", ["cargo", "test", "--doc", "--locked", "--", "--list"], env, True)
        started = time.monotonic()
        try:
            require(cargo_code == nextest_code == doc_code == 0, "Test listing failed")
            cargo_tests = Counter(line[:-6] for line in cargo.splitlines() if line.endswith(": test"))
            doc_tests = [line for line in docs.splitlines() if line.endswith(": test")]
            listing = json.loads(nextest)
            nextest_tests = Counter(name for suite in listing["rust-suites"].values() for name in suite["testcases"])
            require(cargo_tests and cargo_tests == nextest_tests, "Cargo/Nextest test discovery differs")
            require(not doc_tests, "Doctests added: define their execution before migrating test scope")
            self.data["discovery"] = {
                "tests": sum(cargo_tests.values()), "doctests": len(doc_tests),
                "inventory_sha256": hashlib.sha256(json.dumps(sorted(cargo_tests.items())).encode()).hexdigest(),
            }
            code = 0
        except (ValueError, KeyError, TypeError):
            print("Test discovery failed: Cargo/Nextest inventories must agree and doctests require an explicit policy", file=sys.stderr)
            code = 1
        self.data["commands"]["discovery"] = {"exit_code": code}
        self.data["timings_seconds"]["discovery"] = time.monotonic() - started + sum(
            self.data["timings_seconds"][key] for key in ("cargo_list", "nextest_list", "doctest_list"))
        self.save()
        # Listing instrumented binaries may emit counters; discard those before the one real run.
        cleanup, _ = self.command("profile_cleanup", ["cargo", "llvm-cov", "clean", "--profraw-only", "--locked"])
        return code or cleanup

    def test(self):
        require("test" not in self.data["commands"], "Refusing to run the suite twice in one execution")
        require(self.data["commands"]["discovery"]["exit_code"] == 0, "Test discovery did not succeed")
        code, _ = self.command("test", ["cargo", "llvm-cov", "nextest", "--profile", "ci", "--locked",
                                        "--no-tests=fail", "--no-report"])
        junit = self.root / "target/nextest/ci/junit.xml"
        if junit.is_file():
            shutil.copyfile(junit, self.root / "reports/tests/junit.xml")
        return code

    def reports(self):
        directory = self.root / "reports/coverage"
        # Default LLVM exclusions cover dependencies, generated files and *_tests.rs.
        # The positive allowlist is checked again against original files by the validator.
        exclude = r"(^|/)(tests|examples|benches|target|generated|vendor)/|(^|/)[^/]*[_-]tests\.rs$"
        common = ["cargo", "llvm-cov", "report", "--locked", "--ignore-filename-regex", exclude]
        outcomes = []
        for name, flags in (
            ("lcov", ["--lcov", "--output-path", str(directory / "lcov.info")]),
            ("json", ["--json", "--skip-functions", "--output-path", str(directory / "coverage.json")]),
            ("html", ["--html", "--output-dir", str(directory)]),
            ("gate", ["--fail-under-lines", "20"]),
        ):
            code, _ = self.command(name, common + flags)
            outcomes.append(code)
        started = time.monotonic()
        try:
            records = lcov(directory / "lcov.info", self.root, normalize=True)
            coverage(directory / "coverage.json", records, self.root, normalize=True)
            code = 0
        except (OSError, ValueError, KeyError, TypeError):
            code = 1
            print("Coverage normalization/scope validation failed", file=sys.stderr)
        self.data["commands"]["normalization"] = {"exit_code": code}
        self.data["timings_seconds"]["normalization"] = time.monotonic() - started
        outcomes.append(code)
        self.data["report_sha256"] = {
            name: hashlib.sha256((self.root / "reports" / name).read_bytes()).hexdigest()
            for name in ("tests/junit.xml", "coverage/lcov.info", "coverage/coverage.json", "coverage/html/index.html")
            if (self.root / "reports" / name).is_file()
        }
        self.data["completed"] = True
        self.save()
        return 1 if any(outcomes) else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "test", "reports"))
    args = parser.parse_args()
    try:
        execution = Execution(fresh=args.command == "build")
        return getattr(execution, args.command)()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("Test CI stage failed or lacks verified execution context", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
