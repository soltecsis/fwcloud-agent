"""Run both real package post-install entry points with isolated service stubs."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PLACEHOLDER = next(x.split('=', 1)[1].strip('"') for x in (ROOT / '.env.example').read_text().splitlines() if x.startswith('API_KEY='))
LEGACY = 'historical-synthetic-fixture-'.ljust(64, 'L')
LEGITIMATE = 'user-generated-synthetic-fixture-'.ljust(64, 'U')


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='agent-install-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'agent'
        self.root.mkdir()
        (self.root / 'etc').mkdir()
        for name in ['key.pem', 'cert.pem']:
            (self.root / 'etc' / name).touch()
        helper = (ROOT / 'packaging/configure-api-key.sh').read_text()
        helper = re.sub(r'HISTORICAL_SHA256=[0-9a-f]{64}',
                        'HISTORICAL_SHA256=' + hashlib.sha256(LEGACY.encode()).hexdigest(), helper)
        (self.root / 'configure-api-key.sh').write_text(helper)
        self.bin = Path(self.temp.name) / 'bin'; self.bin.mkdir()
        self.calls = Path(self.temp.name) / 'service-calls'
        service = self.bin / 'systemctl'
        service.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$SERVICE_CALLS"\n')
        service.chmod(0o700)
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'SERVICE_CALLS': str(self.calls)}

    def invoke(self, kind, upgrade=False):
        if kind == 'deb':
            script = (ROOT / '.deb/maintainer-scripts/postinst').read_text()
        else:
            script = (ROOT / '.rpm/fwcloud-agent.spec').read_text().split('\n%post\n', 1)[1].split('\n%preun', 1)[0]
        script = script.replace('/opt/fwcloud/agent', str(self.root))
        entry = Path(self.temp.name) / 'postinst'
        entry.write_text(script)
        return subprocess.run(['/bin/sh', str(entry), '2' if upgrade else '1'], env=self.env,
                              capture_output=True, text=True)

    def key(self):
        lines = (self.root / '.env').read_text().splitlines()
        return next(x.split('=', 1)[1].strip('"') for x in lines if x.startswith('API_KEY='))

    def write(self, text, upgrade=False):
        path = self.root / ('.env.upgrade' if upgrade else '.env')
        path.write_text(text)
        return path

    def assert_private(self, result, *keys):
        for key in keys:
            self.assertNotIn(key, result.stdout + result.stderr)

    def test_fresh_deb_and_rpm_generate_distinct_secure_keys(self):
        generated = []
        for kind in ['deb', 'rpm']:
            self.write(f'API_KEY="{PLACEHOLDER}"\n')
            result = self.invoke(kind)
            self.assertEqual(result.returncode, 0, 'post-install failed')
            key = self.key()
            self.assertTrue(re.fullmatch('[a-f0-9]{64}', key) is not None)
            self.assertNotEqual(key, PLACEHOLDER)
            self.assert_private(result, key)
            self.assertEqual(stat.S_IMODE((self.root / '.env').stat().st_mode), 0o600)
            generated.append(key)
        self.assertNotEqual(*generated)

    def test_upgrades_preserve_legitimate_keys_and_other_configuration(self):
        for kind in ['deb', 'rpm']:
            for value in [f'"{LEGITIMATE}"', f"'{LEGITIMATE}'", LEGITIMATE,
                          'U'*16, 'U'*32, 'U'*128, 'synthetic-user-key-with-dashes_and_underscores']:
                self.write(f'API_KEY="{PLACEHOLDER}"\n')
                text = f'PORT=9443\nAPI_KEY={value}\n'
                old = self.write(text, upgrade=True)
                result = self.invoke(kind, upgrade=True)
                self.assertEqual(result.returncode, 0)
                self.assertEqual((self.root / '.env').read_text(), text)
                self.assertFalse(old.exists())
                self.assert_private(result, LEGITIMATE)

    def test_upgrades_rotate_historical_key_and_preserve_other_settings(self):
        for kind in ['deb', 'rpm']:
            self.write(f'API_KEY="{PLACEHOLDER}"\n')
            old = self.write(f'PORT=9443\nAPI_KEY="{LEGACY}"\n', upgrade=True)
            result = self.invoke(kind, upgrade=True)
            self.assertEqual(result.returncode, 0)
            self.assertNotEqual(self.key(), LEGACY)
            self.assertIn('PORT=9443', (self.root / '.env').read_text())
            self.assertFalse(old.exists())
            self.assert_private(result, self.key(), LEGACY)

    def test_missing_malformed_empty_duplicate_and_placeholder_configuration(self):
        for kind in ['deb', 'rpm']:
            for text in [None, '', 'PORT=9443\n', 'API_KEY="short"\n',
                         f'API_KEY="{LEGITIMATE}\n',
                         f'API_KEY="{LEGITIMATE}"\nAPI_KEY="{LEGITIMATE}"\n',
                         f'API_KEY="{PLACEHOLDER}"\n']:
                with self.subTest(kind=kind, case='missing' if text is None else 'invalid'):
                    (self.root / '.env').unlink(missing_ok=True)
                    if text is not None:
                        self.write(text)
                    result = self.invoke(kind)
                    self.assertEqual(result.returncode, 0)
                    self.assertTrue(re.fullmatch('[a-f0-9]{64}', self.key()) is not None)
                    self.assert_private(result, self.key())

    def test_generation_failure_preserves_upgrade_and_never_starts_service(self):
        openssl = self.bin / 'openssl'
        for response in ['exit 9', "printf 'short'", "printf '%064d' 0; exit 9"]:
            openssl.write_text('#!/bin/sh\nif [ "$1" != rand ]; then exec /usr/bin/openssl "$@"; fi\n' + response + '\n'); openssl.chmod(0o700)
            for kind in ['deb', 'rpm']:
                self.calls.unlink(missing_ok=True)
                current = self.write(f'API_KEY="{PLACEHOLDER}"\n')
                backup = self.write(f'PORT=9443\nAPI_KEY="{LEGACY}"\n', upgrade=True)
                previous = backup.read_bytes()
                result = self.invoke(kind, upgrade=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(backup.read_bytes(), previous)
                self.assertEqual(current.read_text(), f'API_KEY="{PLACEHOLDER}"\n')
                self.assertFalse(list(self.root.glob('.env.????????')))
                calls = self.calls.read_text() if self.calls.exists() else ''
                self.assertNotIn('start', calls)
                self.assertNotIn('enable', calls)
                self.assert_private(result, LEGACY)

    def test_upgrade_backup_symlinks_fail_closed(self):
        self.write(f'API_KEY="{PLACEHOLDER}"\n')
        outside = Path(self.temp.name) / 'outside'; outside.write_text('unchanged')
        (self.root / '.env.upgrade').symlink_to(outside)
        for kind in ['deb', 'rpm']:
            self.assertNotEqual(self.invoke(kind, upgrade=True).returncode, 0)
        self.assertEqual(outside.read_text(), 'unchanged')

    def test_preinstall_does_not_overwrite_an_existing_backup_or_fail_when_env_is_missing(self):
        for kind in ['deb', 'rpm']:
            source = (ROOT / ('.deb/maintainer-scripts/preinst' if kind == 'deb' else '.rpm/fwcloud-agent.spec')).read_text()
            if kind == 'rpm':
                source = source.split('\n%pre\n', 1)[1].split('\n%post', 1)[0]
            source = source.replace('/opt/fwcloud/agent', str(self.root))
            entry = Path(self.temp.name) / 'preinst'; entry.write_text(source)
            for existing in [False, True]:
                current = self.root / '.env'; current.unlink(missing_ok=True)
                if existing:
                    self.write(f'API_KEY="{PLACEHOLDER}"\n')
                backup = self.write(f'API_KEY="{LEGITIMATE}"\n', upgrade=True)
                result = subprocess.run(['/bin/sh', str(entry), 'upgrade' if kind == 'deb' else '2'],
                                        env=self.env, capture_output=True)
                self.assertEqual(result.returncode, 0)
                self.assertIn(LEGITIMATE, backup.read_text())
