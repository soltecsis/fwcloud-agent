#!/usr/bin/env python3
"""Regression tests for pinned inputs and CI evidence; no Rust downloads."""

from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("rust_ci", Path(__file__).with_name("rust-ci.py"))
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)

COMMIT = "1" * 40
RUST_COMMIT = "58cf8f9c35b355199727627d07ae34a4e2846d67"
VERSIONS = {
    ("git", "rev-parse", "HEAD"): COMMIT,
    ("rustc", "--version", "--verbose"):
        f"rustc 1.99.1 ({RUST_COMMIT[:9]} 2026-10-13)\n"
        f"commit-hash: {RUST_COMMIT}\nrelease: 1.99.1",
    ("cargo", "--version", "--verbose"): "cargo 1.99.1 (5f94df478 2026-08-27)",
    ("cargo", "fmt", "--version"): f"rustfmt 1.10.0-stable ({RUST_COMMIT[:10]} 2026-10-13)",
    ("cargo", "clippy", "--version"): f"clippy 0.1.99 ({RUST_COMMIT[:10]} 2026-10-13)",
    ("cargo", "rpm", "version"): "cargo-rpm 0.8.0",
    ("cargo-audit", "--version"): "cargo-audit 0.22.2",
    ("cargo-tarpaulin", "--version"): "tarpaulin 0.37.5",
    ("cargo-deb", "--version"): "cargo-deb 3.8.0",
}


class RustCiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / ".github").mkdir()
        self.toolchain = (
            '[toolchain]\nchannel = "1.99.1"\nprofile = "minimal"\n'
            'components = ["rustfmt", "clippy"]\n'
        )
        (self.root / "rust-toolchain.toml").write_text(self.toolchain)
        (self.root / ".github/ci-tools.toml").write_text(
            (ci.ROOT / ".github/ci-tools.toml").read_text()
        )
        (self.root / "Cargo.lock").write_text("version = 4\n")
        self.env = {
            "ANALYSIS_COMMIT": COMMIT,
            "GITHUB_REPOSITORY": "soltecsis/fwcloud-agent",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_WORKFLOW": "FWCloud-Agent CI",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REF": "refs/pull/1/merge",
            "GITHUB_JOB": "quality",
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "ImageOS": "ubuntu24",
            "ImageVersion": "20261101.1.0",
            "RUNNER_TEMP": str(self.root / "runner"),
            "GITHUB_ENV": str(self.root / "env"),
            "GITHUB_PATH": str(self.root / "path"),
            "PATH": "/usr/bin",
        }

    def version_output(self, command, **_kwargs):
        return VERSIONS[tuple(command)]

    def record(self, env=None, tool="", versions=None):
        values = VERSIONS if versions is None else versions
        with patch.object(ci, "output", side_effect=lambda command, **kwargs: values[tuple(command)]):
            with redirect_stdout(io.StringIO()):
                return ci.record(env or self.env, tool, self.root)

    def test_exact_toolchain_and_utility_pins(self):
        toolchain, tools = ci.read_pins(self.root)
        self.assertEqual(toolchain["channel"], "1.99.1")
        self.assertEqual(set(tools), set(ci.TOOL_COMMANDS))
        for replacement in ("stable", "nightly", "1.99", "1.99.1-beta.1"):
            with self.subTest(replacement=replacement):
                (self.root / "rust-toolchain.toml").write_text(
                    self.toolchain.replace("1.99.1", replacement)
                )
                with self.assertRaises(ValueError):
                    ci.read_pins(self.root)

    def test_required_components_and_minimal_profile(self):
        for before, after in (("minimal", "default"), ('"rustfmt", "clippy"', '"rustfmt"')):
            with self.subTest(after=after):
                (self.root / "rust-toolchain.toml").write_text(self.toolchain.replace(before, after))
                with self.assertRaises(ValueError):
                    ci.read_pins(self.root)

    def test_installed_release_and_component_mismatch_fail_closed(self):
        replacements = {
            ("rustc", "--version", "--verbose"): VERSIONS[("rustc", "--version", "--verbose")].replace("release: 1.99.1", "release: 1.99.0"),
            ("cargo", "--version", "--verbose"): "cargo 1.98.0 (abc 2026-01-01)",
            ("cargo", "fmt", "--version"): "rustfmt 1.10.0-stable (fffffffff 2026-01-01)",
            ("cargo", "clippy", "--version"): "clippy 0.1.99 (fffffffff 2026-01-01)",
            ("cargo", "rpm", "version"): "cargo-rpm 0.7.0",
        }
        for command, actual in replacements.items():
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    self.record(tool="cargo-rpm", versions=VERSIONS | {command: actual})

    def test_metadata_binds_revision_attempt_lockfile_and_versions(self):
        result = self.record(tool="cargo-rpm")
        self.assertEqual(result["source_commit"], COMMIT)
        self.assertEqual(result["run_attempt"], "2")
        self.assertEqual(result["runner_os"], "Linux")
        self.assertEqual(result["runner_arch"], "X64")
        self.assertEqual(result["runner_image_os"], "ubuntu24")
        self.assertEqual(result["runner_image_version"], "20261101.1.0")
        self.assertEqual(result["cargo_lock_sha256"], hashlib.sha256(b"version = 4\n").hexdigest())
        self.assertEqual(result["installed"]["cargo-rpm"], "cargo-rpm 0.8.0")
        self.assertEqual(json.loads((self.root / "reports/ci/quality.json").read_text()), result)

    def test_revision_mismatch_and_missing_context_fail(self):
        with self.assertRaises(ValueError):
            self.record(versions=VERSIONS | {("git", "rev-parse", "HEAD"): "2" * 40})
        for name in ("ANALYSIS_COMMIT", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"):
            with self.subTest(name=name):
                env = self.env.copy()
                del env[name]
                with self.assertRaises(ValueError):
                    self.record(env)

    def test_invalid_context_and_missing_lockfile_fail(self):
        for name, value in (("ANALYSIS_COMMIT", "main"), ("GITHUB_JOB", "../../evidence"),
                            ("GITHUB_RUN_ATTEMPT", "0"), ("GITHUB_REPOSITORY", "invalid/repository/path")):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    self.record(self.env | {name: value})
        (self.root / "Cargo.lock").unlink()
        with self.assertRaises(FileNotFoundError):
            self.record()

    def test_evidence_and_log_exclude_credentials(self):
        env = self.env | {"GITHUB_TOKEN": "secret-sentinel", "SONAR_TOKEN": "secret-sentinel"}
        captured = io.StringIO()
        with patch.object(ci, "output", side_effect=self.version_output), redirect_stdout(captured):
            result = ci.record(env, root=self.root)
        self.assertNotIn("secret-sentinel", json.dumps(result) + captured.getvalue())
        self.assertNotIn("GITHUB_TOKEN", json.dumps(result) + captured.getvalue())

    def test_component_hash_must_match_inside_version_provenance(self):
        rustfmt = ("cargo", "fmt", "--version")
        for actual in (f"rustfmt 1.10.0-stable ({RUST_COMMIT[:8]} 2026-10-13)",
                       f"rustfmt 1.10.0-stable (fffffffff 2026-10-13) {RUST_COMMIT[:9]}"):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                self.record(versions=VERSIONS | {rustfmt: actual})

    def test_setup_installs_locked_versions_and_exports_toolchain_and_path(self):
        with patch.object(ci.subprocess, "run") as run:
            with patch.object(ci, "output", side_effect=self.version_output):
                with redirect_stdout(io.StringIO()):
                    ci.setup(self.env | {"CI_CARGO_TOOL": "cargo-rpm"}, self.root)
        rustup, cargo = [call.args[0] for call in run.call_args_list]
        self.assertIn("--no-self-update", rustup)
        self.assertIn("1.99.1", rustup)
        self.assertNotIn("default", rustup)
        self.assertEqual(cargo, ["cargo", "install", "--locked", "--version", "=0.8.0",
                                 "--registry", "crates-io", "--root",
                                 str(self.root / "runner/agent-ci-tools"), "cargo-rpm"])
        self.assertEqual((self.root / "env").read_text(), "RUSTUP_TOOLCHAIN=1.99.1\n")
        self.assertEqual((self.root / "path").read_text(), str(self.root / "runner/agent-ci-tools/bin") + "\n")
        self.assertEqual(run.call_args.kwargs["env"]["RUSTUP_TOOLCHAIN"], "1.99.1")

    def test_unknown_utility_is_rejected_before_install(self):
        with patch.object(ci.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                ci.setup(self.env | {"CI_CARGO_TOOL": "arbitrary-package"}, self.root)
        run.assert_not_called()

    def test_utility_version_commands_match_native_output(self):
        for tool, command in ci.TOOL_COMMANDS.items():
            with self.subTest(tool=tool):
                metadata = self.record(tool=tool)
                self.assertEqual(metadata["installed"][tool], VERSIONS[tuple(command)])
        # Cargo passes the subcommand to the plugin; clap then repeats the name.
        # Version checks invoke these executables directly to avoid that prefix.
        for tool in ("cargo-audit", "cargo-tarpaulin"):
            self.assertEqual(ci.TOOL_COMMANDS[tool], [tool, "--version"])
        self.assertEqual(ci.TOOL_COMMANDS["cargo-rpm"], ["cargo", "rpm", "version"])


if __name__ == "__main__":
    unittest.main()
