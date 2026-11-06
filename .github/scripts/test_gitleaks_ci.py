"""Scope, extraction and actual-scanner regressions with synthetic credentials only."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('gitleaks_ci', Path(__file__).with_name('gitleaks-ci.py'))
ci = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ci)
# Assembled at runtime; never a usable provider credential.
SYNTHETIC = 'gh' + 'p_' + hashlib.sha256(b'FWCloud synthetic regression fixture').hexdigest()[:36]


def run(args, root, env=None):
    result = subprocess.run(args, cwd=root, env=env, capture_output=True)
    if result.returncode:
        raise AssertionError('Fixture command failed; output withheld')
    return result.stdout.decode().strip()


def cpio_member(name, content=b'', mode=stat.S_IFREG | 0o600, links=1):
    encoded = name.encode() + b'\0'
    fields = [1, mode, 0, 0, links, 0, len(content), 0, 0, 0, 0, len(encoded), 0]
    header = b'070701' + ''.join(f'{n:08x}' for n in fields).encode()
    return header + encoded + b'\0' * (-(110 + len(encoded)) % 4) + content + b'\0' * (-len(content) % 4)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='agent-gitleaks-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, 'RUNNER_TEMP': self.tmp.name,
                    'GITHUB_REPOSITORY': 'soltecsis/fwcloud-agent', 'GITHUB_RUN_ID': '240',
                    'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'GITHUB_STEP_SUMMARY': str(self.root / 'summary.md'),
                    'GITHUB_OUTPUT': str(self.root / 'outputs'),
                    'GITHUB_EVENT_PATH': str(self.root / 'event.json')}
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        (self.root / '.gitleaks.toml').write_text((ci.ROOT / '.gitleaks.toml').read_text())
        self.base = self.commit()
        self.env['ANALYSIS_COMMIT'] = self.base
        (self.root / 'event.json').write_text('{}')

    def git(self, *args):
        return run(['git', *args], self.root, ci.environment(self.env))

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'Synthetic fixture', '--allow-empty')
        return self.git('rev-parse', 'HEAD')


class PolicyScopeTests(Fixture):
    def test_event_ranges_use_actual_commits(self):
        before = self.base
        (self.root / 'sample').write_text('first')
        middle = self.commit()
        (self.root / 'sample').unlink()
        head = self.commit(); self.env['ANALYSIS_COMMIT'] = head
        for external in [False, True]:
            self.env['GITHUB_EVENT_NAME'] = 'pull_request'
            event = {'pull_request': {'base': {'sha': before}, 'head': {'sha': head, 'repo': {'fork': external}}}}
            result = ci.scope(self.root, self.env, event)
            self.assertEqual(result, {'scope': 'pull-request', 'log_opts': before+'..'+head, 'commit_count': '2'})
        self.env['GITHUB_EVENT_NAME'] = 'push'
        self.assertEqual(ci.scope(self.root, self.env, {'before': middle, 'after': head})['commit_count'], '1')
        self.assertEqual(ci.scope(self.root, self.env, {'before': '0'*40, 'after': head})['commit_count'], '3')
        self.env['GITHUB_EVENT_NAME'] = 'workflow_dispatch'
        self.assertEqual(ci.scope(self.root, self.env, {})['log_opts'], '--all')

    def test_invalid_events_commits_missing_refs_and_shallow_history_fail(self):
        for value in ['--all', '--output=/tmp/leak', '', None, 'f'*40]:
            with self.assertRaises(ValueError):
                ci.commit(self.root, self.env, value)
        for event in ['pull_request_target', 'schedule', '', 'unknown']:
            with self.assertRaises(ValueError):
                ci.scope(self.root, {**self.env, 'GITHUB_EVENT_NAME': event}, {})
        with self.assertRaises(ValueError):
            ci.scope(self.root, {**self.env, 'GITHUB_EVENT_NAME': 'push'}, {'before': 'f'*40, 'after': self.base})
        (self.root / '.git/shallow').write_text(self.base+'\n')
        with self.assertRaises(ValueError):
            ci.scope(self.root, self.env, {})

    def test_policy_rejects_ignore_files_and_any_configuration_override(self):
        ci.policy(self.root, self.env)
        ignore = self.root / '.gitleaksignore'
        for dangling in [False, True]:
            if dangling: ignore.symlink_to(self.root / 'missing')
            else: ignore.touch()
            with self.assertRaises(ValueError): ci.policy(self.root, self.env)
            ignore.unlink()
        config = self.root / '.gitleaks.toml'
        original = config.read_text()
        for extra in ['\n[allowlist]\npaths=[".*"]\n', '\n[[rules]]\nid="override"\n', '\n[extend.allowlist]\nregexes=[".*"]\n']:
            config.write_text(original+extra)
            with self.assertRaises(ValueError): ci.policy(self.root, self.env)
        config.write_text(original)
        nested = self.root / 'nested'; nested.mkdir()
        (nested / '.gitleaksignore').touch()
        with self.assertRaises(ValueError): ci.policy(self.root, self.env)
        self.git('add', '.')
        with self.assertRaises(ValueError): ci.policy(self.root, self.env)

    def test_ambient_git_and_gitleaks_configuration_are_removed(self):
        clean = ci.environment({'GITLEAKS_CONFIG_TOML': 'override', 'GIT_DIR': 'other', 'GIT_CONFIG_COUNT': '1', 'PATH': '/bin'})
        self.assertEqual(clean, {'PATH': '/bin'})

    def test_failed_scanner_preserves_native_status_and_withholds_output(self):
        binary = self.root / 'scanner'
        binary.write_text('#!/bin/sh\nif [ "$1" = version ]; then echo 8.30.1; exit 0; fi\necho "private/path: secret" >&2\nexit 37\n')
        binary.chmod(0o700)
        self.env['GITLEAKS_BINARY'] = str(binary)
        ci.prepare(self.root, 'history')
        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            code = ci.scan(self.root, self.env, 'history')
        self.assertEqual(code, 37)
        self.assertEqual(stdout.getvalue()+stderr.getvalue(), '')
        self.assertIn('exit_code=37', (self.root/'outputs').read_text())

    def test_checksum_failure_prevents_extraction_and_version_verification(self):
        self.env['GITHUB_ENV'] = str(self.root / 'env')
        def download(args, *unused, **kwargs):
            Path(args[-1]).write_bytes(b'not the official archive')
        with patch.object(ci, 'execute', side_effect=download), patch.object(ci.tarfile, 'open') as tar:
            with self.assertRaises(ValueError): ci.install(self.env)
            tar.assert_not_called()


class ExtractionTests(Fixture):
    def test_tar_rejects_traversal_absolute_paths_links_and_devices(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('C:/escape', tarfile.REGTYPE), ('safe', tarfile.SYMTYPE),
                           ('hardlink', tarfile.LNKTYPE), ('device', tarfile.CHRTYPE)]:
            with self.subTest(kind=kind, name=name):
                archive = self.root / 'bad.tar'
                with tarfile.open(archive, 'w') as tar:
                    member = tarfile.TarInfo(name); member.type = kind; member.linkname = '../escape'
                    tar.addfile(member)
                with self.assertRaises(ValueError): ci.extract_tar(archive, self.root / 'extract')
        self.assertFalse((self.root / 'escape').exists())

    def test_cpio_extracts_files_and_rejects_unsafe_members_and_truncation(self):
        archive = self.root / 'members.cpio'
        archive.write_bytes(cpio_member('directory/file', b'content') + cpio_member('TRAILER!!!'))
        dest = self.root / 'good'; dest.mkdir()
        ci.extract_cpio(archive, dest)
        self.assertEqual((dest / 'directory/file').read_bytes(), b'content')
        for entry in [cpio_member('../escape'), cpio_member('/escape'),
                      cpio_member('symlink', b'../escape', stat.S_IFLNK | 0o777),
                      cpio_member('hardlink', links=2), b'070701',
                      cpio_member('dup') + cpio_member('dup')]:
            archive.write_bytes(entry + cpio_member('TRAILER!!!'))
            with tempfile.TemporaryDirectory(dir=self.root) as tmp:
                with self.assertRaises((ValueError, OSError)): ci.extract_cpio(archive, Path(tmp))

    def test_missing_empty_invalid_and_multiple_packages_fail(self):
        for kind, directory in [('deb', 'packages/deb'), ('rpm', 'target/x86_64-unknown-linux-musl/release/rpmbuild/RPMS/x86_64')]:
            dest = self.root / directory; dest.mkdir(parents=True)
            with tempfile.TemporaryDirectory(dir=self.root) as tmp:
                with self.assertRaises(ValueError): ci.package(self.root, self.env, kind, Path(tmp))
            file = dest / f'bad.{kind}'
            for data in [b'', b'not a package']:
                file.write_bytes(data)
                with tempfile.TemporaryDirectory(dir=self.root) as tmp:
                    with self.assertRaises((ValueError, FileNotFoundError)): ci.package(self.root, self.env, kind, Path(tmp))
            (dest / f'other.{kind}').touch()
            with tempfile.TemporaryDirectory(dir=self.root) as tmp:
                with self.assertRaises(ValueError): ci.package(self.root, self.env, kind, Path(tmp))


@unittest.skipUnless(os.environ.get('RUN_SECRET_INTEGRATION') == '1', 'Actual-scanner tests run in the secrets job')
class ActualScannerTests(Fixture):
    @classmethod
    def setUpClass(cls):
        for tool in ['dpkg-deb', 'rpm', 'rpmkeys', 'rpmbuild', 'rpm2cpio', 'cc']:
            if not shutil.which(tool): raise AssertionError('Required package fixture tool is unavailable')
        if not Path(os.environ.get('GITLEAKS_BINARY', '')).is_file():
            raise AssertionError('Verified Gitleaks binary is required')

    def scan(self, kind):
        ci.prepare(self.root, kind)
        self.env['GITLEAKS_BINARY'] = os.environ['GITLEAKS_BINARY']
        code = ci.scan(self.root, self.env, kind)
        report = ci.report_dir(self.root, kind) / 'gitleaks.json'
        findings = json.loads(report.read_text()) if report.exists() else None
        if findings is None: raise AssertionError('Scanner failed to produce evidence')
        fields = dict(line.split('=', 1) for line in (self.root/'outputs').read_text().splitlines())
        metadata_env = {**self.env, 'GITLEAKS_VERSION': ci.VERSION,
                        'GITLEAKS_REPORT_PATH': str(report),
                        'GITLEAKS_METADATA_PATH': str(ci.report_dir(self.root, kind)/'metadata.json')}
        for key, value in fields.items(): metadata_env['GITLEAKS_'+key.upper()] = value
        collected = subprocess.run(['node', str(ci.ROOT/'scripts/gitleaks-report.cjs')], cwd=self.root,
                                   env=metadata_env, capture_output=True)
        self.assertNotIn(SYNTHETIC.encode(), collected.stdout+collected.stderr)
        metadata = json.loads((ci.report_dir(self.root, kind)/'metadata.json').read_text())
        self.assertFalse(report.exists())
        self.assertNotIn(SYNTHETIC, json.dumps(metadata))
        self.assertNotIn('File', json.dumps(metadata))
        self.assertEqual(collected.returncode, int(metadata['status'] != 'success'))
        # The native scan failure remains a failure after collection/publication.
        self.assertEqual(code, fields.get('exit_code') and int(fields['exit_code']))
        return code, findings, metadata

    def payload(self, secret=False, env_secret=False):
        tree = self.root / 'package-input'; shutil.rmtree(tree, ignore_errors=True)
        agent = tree/'opt/fwcloud/agent'; (agent/'plugins').mkdir(parents=True)
        (agent/'.env').write_text(f'token="{SYNTHETIC}"\n' if env_secret else 'PORT=8888\n')
        (agent/'configure-api-key.sh').write_text('#!/bin/sh\nexit 0\n')
        (agent/'plugins/example.sh').write_text('#!/bin/sh\n'+ (f'token="{SYNTHETIC}"\n' if secret else 'exit 0\n'))
        return tree

    def build_package(self, kind, secret=False, script_secret=False, env_secret=False):
        tree = self.payload(secret, env_secret)
        script = f'echo "{SYNTHETIC}"\n' if script_secret else ':\n'
        if kind == 'deb':
            control = tree/'DEBIAN'; control.mkdir()
            (control/'control').write_text('Package: synthetic-agent\nVersion: 1.0\nArchitecture: amd64\nMaintainer: Fixture <fixture@example.invalid>\nDescription: synthetic regression package\n')
            post = control/'postinst'; post.write_text('#!/bin/sh\n'+script); post.chmod(0o755)
            output = self.root/'packages/deb'; output.mkdir(parents=True, exist_ok=True)
            run(['dpkg-deb', '--build', '--root-owner-group', str(tree), str(output/'fixture.deb')], self.root, self.env)
        else:
            output = self.root/'target/x86_64-unknown-linux-musl/release/rpmbuild/RPMS/x86_64'
            output.mkdir(parents=True, exist_ok=True)
            spec = self.root/'fixture.spec'
            spec.write_text(f'''%define __os_install_post %{{nil}}
%define _build_id_links none
Name: synthetic-agent
Version: 1.0
Release: 1
Summary: synthetic regression package
License: MIT
AutoReqProv: no
%description
Synthetic fixture
%install
mkdir -p %{{buildroot}}
cp -a {tree}/opt %{{buildroot}}/
%files
/opt/fwcloud/agent
%post
{script}
''')
            run(['rpmbuild', '-bb', '--define', f'_topdir {self.root}/rpmbuild', '--define',
                 f'_rpmdir {output}', '--define', '_rpmfilename fixture.rpm', str(spec)], self.root, self.env)

    def test_pr_detects_secret_introduced_then_removed_and_ignores_inline_allow(self):
        # A repository-controlled binary attribute must not hide the Git diff.
        (self.root/'.gitattributes').write_text('synthetic.txt -diff\n')
        (self.root/'synthetic.txt').write_text(f'token="{SYNTHETIC}" # gitleaks:allow\n')
        self.commit()
        (self.root/'synthetic.txt').unlink()
        head = self.commit(); self.env['ANALYSIS_COMMIT'] = head
        self.env['GITHUB_EVENT_NAME'] = 'pull_request'
        (self.root/'event.json').write_text(json.dumps({'pull_request': {'base': {'sha': self.base}, 'head': {'sha': head}}}))
        code, findings, metadata = self.scan('history')
        self.assertEqual(code, 1)
        self.assertTrue(findings)
        self.assertEqual(metadata['status'], 'findings')
        self.assertEqual(metadata['commitCount'], 2)

    def test_clean_git_history_succeeds(self):
        code, findings, metadata = self.scan('history')
        self.assertEqual((code, findings, metadata['status']), (0, [], 'success'))

    def test_merge_resolution_commit_is_scanned(self):
        self.git('checkout', '-qb', 'other')
        other = self.commit()
        self.git('checkout', '--detach', self.base)
        (self.root/'synthetic.txt').write_text(f'token="{SYNTHETIC}"\n')
        self.git('add', 'synthetic.txt')
        tree = self.git('write-tree')
        head = self.git('commit-tree', tree, '-p', self.base, '-p', other, '-m', 'Synthetic merge resolution')
        self.git('checkout', '--detach', head)
        self.env['ANALYSIS_COMMIT'] = head
        (self.root/'event.json').write_text('{}')
        code, findings, metadata = self.scan('history')
        self.assertEqual(code, 1)
        self.assertTrue(findings)
        self.assertEqual(metadata['status'], 'findings')

    def test_actual_deb_and_rpm_payloads_and_install_scripts_are_scanned(self):
        for kind in ['deb', 'rpm']:
            for secret, script_secret, env_secret in [(False, False, False), (True, False, False),
                                                       (False, True, False), (False, False, True)]:
                with self.subTest(kind=kind, secret=secret, script_secret=script_secret, env_secret=env_secret):
                    self.build_package(kind, secret, script_secret, env_secret)
                    code, findings, metadata = self.scan(kind)
                    expected = int(secret or script_secret or env_secret)
                    self.assertEqual(code, expected)
                    self.assertEqual(bool(findings), bool(expected))
                    self.assertEqual(metadata['status'], 'findings' if expected else 'success')
                    self.assertEqual(metadata['packageType'], kind)
                    self.assertRegex(metadata['packageSha256'], '^[0-9a-f]{64}$')

    def test_production_rpm_spec_with_elf_passes_distribution_scan(self):
        # A text-only fixture cannot expose RPM's generated build-ID symlinks.
        manifest = tomllib.loads((ci.ROOT / 'Cargo.toml').read_text())['package']
        version = manifest['version']
        name = f'fwcloud-agent-{version}'
        source = self.root / name
        source.mkdir()
        for origin, metadata in manifest['metadata']['rpm']['files'].items():
            original = (ci.ROOT / '.rpm' / origin).resolve()
            self.assertTrue(original.is_relative_to(ci.ROOT))
            destination = source / metadata['path'].lstrip('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, destination)
        code = self.root / 'synthetic.c'
        code.write_text('int main(void) { return 0; }\n')
        run(['cc', '-Wl,--build-id', str(code), '-o',
             str(source / 'opt/fwcloud/agent/fwcloud-agent')], self.root, self.env)
        top = self.root / 'production-rpmbuild'
        (top / 'SOURCES').mkdir(parents=True)
        with tarfile.open(top / 'SOURCES' / f'{name}.tar.gz', 'w:gz') as archive:
            archive.add(source, arcname=name)
        spec = (ci.ROOT / '.rpm/fwcloud-agent.spec').read_text()
        spec = spec.replace('@@VERSION@@', version).replace('@@RELEASE@@', '1')
        spec_path = self.root / 'production.spec'
        spec_path.write_text(spec)
        output = self.root / 'target/x86_64-unknown-linux-musl/release/rpmbuild/RPMS/x86_64'
        output.mkdir(parents=True)
        # Model RPM 4's default profile. The production spec must override it;
        # unlike minimal fixtures, this test never injects a "none" override.
        run(['rpmbuild', '-bb', '--define', f'_topdir {top}', '--define',
             f'_rpmdir {output}', '--define', '_rpmfilename fixture.rpm',
             '--define', '_build_id_links compat', str(spec_path)], self.root, self.env)
        status, findings, metadata = self.scan('rpm')
        self.assertEqual(status, 0)
        self.assertEqual(findings, [])
        self.assertEqual(metadata['status'], 'success')
        self.assertEqual(metadata['packageType'], 'rpm')
