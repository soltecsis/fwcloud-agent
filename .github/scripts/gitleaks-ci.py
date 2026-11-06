#!/usr/bin/env python3
"""Pinned secret scanning; subprocess output and package members remain private."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
VERSION = '8.30.1'
SHA256 = '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb'
CONFIG = {'title': 'FWCloud-Agent Gitleaks configuration', 'minVersion': 'v8.30.1',
          'extend': {'useDefault': True}}


def require(condition, category):
    if not condition:
        raise ValueError(category)


def environment(env):
    # Neither ambient Gitleaks settings nor Git alternate stores/config may alter scope.
    return {k: v for k, v in env.items() if not k.startswith(('GITLEAKS_', 'GIT_'))}


def execute(args, root, env, **kwargs):
    result = subprocess.run(args, cwd=root, env=environment(env), stderr=subprocess.PIPE,
                            timeout=180, **kwargs)
    require(result.returncode == 0, 'subprocess_failed')
    return result


def git(root, env, *args):
    return execute(['git', *args], root, env, stdout=subprocess.PIPE).stdout.decode().strip()


def commit(root, env, value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value)
            and value != '0' * 40, 'invalid_commit')
    require(git(root, env, 'cat-file', '-t', value) == 'commit', 'missing_commit')
    return value


def scope(root, env, event):
    head = commit(root, env, env.get('ANALYSIS_COMMIT'))
    require(git(root, env, 'rev-parse', 'HEAD') == head, 'checkout_mismatch')
    require(git(root, env, 'rev-parse', '--is-shallow-repository') == 'false', 'shallow_history')
    name = env.get('GITHUB_EVENT_NAME')
    if name == 'pull_request':
        require(event['pull_request']['head']['sha'] == head, 'event_head_mismatch')
        base = commit(root, env, event['pull_request']['base']['sha'])
        bases = git(root, env, 'merge-base', '--all', base, head).splitlines()
        require(len(bases) == 1, 'ambiguous_merge_base')
        merge_base = commit(root, env, bases[0])
        category, options = 'pull-request', f'{merge_base}..{head}'
    elif name == 'push':
        require(event['after'] == head, 'event_head_mismatch')
        before = event['before']
        require(isinstance(before, str) and re.fullmatch('[0-9a-f]{40}', before), 'invalid_before')
        if before == '0' * 40:
            category, options = 'new-branch-history', head
        else:
            commit(root, env, before)
            category, options = 'push', f'{before}..{head}'
    elif name == 'workflow_dispatch':
        category, options = 'full-history', '--all'
    else:
        raise ValueError('unsupported_event')
    count = git(root, env, 'rev-list', '--count', options)
    require(count.isdigit(), 'invalid_history_count')
    return {'scope': category, 'log_opts': options, 'commit_count': count}


def policy(root, env):
    config = root / '.gitleaks.toml'
    require(not config.is_symlink() and tomllib.loads(config.read_text()) == CONFIG, 'invalid_policy')
    require(not os.path.lexists(root / '.gitleaksignore'), 'forbidden_ignore_file')
    tracked = execute(['git', 'ls-files', '-z'], root, env, stdout=subprocess.PIPE).stdout.split(b'\0')
    require(not any(p.split(b'/')[-1] == b'.gitleaksignore' for p in tracked), 'forbidden_ignore_file')
    def traversal_error(error):
        raise error
    for _, directories, names in os.walk(root, onerror=traversal_error):
        directories[:] = [name for name in directories if name != '.git']
        require('.gitleaksignore' not in names + directories, 'forbidden_ignore_file')


def verify_version(binary, env):
    result = execute([str(binary), 'version'], ROOT, env, stdout=subprocess.PIPE)
    require(result.stdout.decode().strip() == VERSION and not result.stderr, 'invalid_version')


def install(env):
    destination = Path(env['RUNNER_TEMP']) / 'agent-gitleaks'
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination) as tmp:
        archive = Path(tmp) / f'gitleaks_{VERSION}_linux_x64.tar.gz'
        execute(['curl', '--fail', '--silent', '--show-error', '--location', '--connect-timeout', '15',
                 '--max-time', '120', f'https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/{archive.name}',
                 '--output', str(archive)], ROOT, env, stdout=subprocess.PIPE)
        require(hashlib.sha256(archive.read_bytes()).hexdigest() == SHA256, 'checksum_mismatch')
        with tarfile.open(archive) as tar:
            member = tar.getmember('gitleaks')
            require(member.isfile(), 'invalid_binary_archive')
            binary = destination / 'gitleaks'
            binary.write_bytes(tar.extractfile(member).read())
        binary.chmod(0o700)
    verify_version(binary, env)
    with Path(env['GITHUB_ENV']).open('a') as output:
        output.write(f'GITLEAKS_BINARY={binary}\n')
    print(f'Gitleaks {VERSION}: archive SHA-256 and installed version verified.')


def safe_name(name):
    require(isinstance(name, str) and '\x00' not in name and '\\' not in name
            and not name.startswith('/') and not re.match('[A-Za-z]:', name), 'unsafe_package_path')
    path = PurePosixPath(name)
    require('..' not in path.parts, 'unsafe_package_path')
    return path


def write_member(destination, name, data, directory, seen):
    name = safe_name(name)
    if str(name) == '.':
        require(directory, 'invalid_package_root')
        return
    require(name not in seen, 'duplicate_package_path')
    seen.add(name)
    target = destination / str(name)
    require(target.resolve().is_relative_to(destination.resolve()), 'unsafe_package_path')
    if directory:
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as output:
            output.write(data)
        target.chmod(0o600)


def extract_tar(archive, destination):
    seen = set()
    with tarfile.open(archive, mode='r:*') as tar:
        for member in tar:
            # Reject all links/devices/FIFOs rather than letting extraction follow them.
            require(member.isdir() or member.isfile(), 'unsafe_package_member')
            data = b'' if member.isdir() else tar.extractfile(member).read()
            write_member(destination, member.name, data, member.isdir(), seen)
    require(seen, 'empty_package')


def exact(stream, length):
    require(0 <= length <= 2 ** 31, 'invalid_cpio_size')
    data = stream.read(length)
    require(len(data) == length, 'truncated_cpio')
    return data


def extract_cpio(archive, destination):
    seen = set()
    with Path(archive).open('rb') as stream:
        while True:
            header = exact(stream, 110)
            require(header[:6] in (b'070701', b'070702'), 'invalid_cpio_header')
            values = [int(header[6+i*8:14+i*8], 16) for i in range(13)]
            mode, links, size, namesize, checksum = values[1], values[4], values[6], values[11], values[12]
            require(0 < namesize <= 4096, 'invalid_cpio_name')
            raw_name = exact(stream, namesize)
            require(raw_name.endswith(b'\0') and b'\0' not in raw_name[:-1], 'invalid_cpio_name')
            name = raw_name[:-1].decode('utf8')
            exact(stream, -(110 + namesize) % 4)
            data = exact(stream, size)
            exact(stream, -size % 4)
            if header[:6] == b'070702':
                require(sum(data) % 2**32 == checksum, 'invalid_cpio_checksum')
            if name == 'TRAILER!!!':
                require(size == 0 and not stream.read().strip(b'\0'), 'invalid_cpio_trailer')
                break
            directory = stat.S_ISDIR(mode)
            require(directory or (stat.S_ISREG(mode) and links == 1), 'unsafe_package_member')
            write_member(destination, name, data, directory, seen)
    require(seen, 'empty_package')


def package(root, env, kind, temporary):
    pattern = 'packages/deb/*.deb' if kind == 'deb' else 'target/x86_64-unknown-linux-musl/release/rpmbuild/RPMS/x86_64/*.rpm'
    packages = list(root.glob(pattern))
    require(len(packages) == 1, 'missing_or_ambiguous_package')
    archive = packages[0]
    require(not archive.is_symlink() and archive.is_file() and archive.stat().st_size > 0, 'invalid_package')
    require(archive.resolve().is_relative_to(root.resolve()), 'unsafe_package_path')
    with archive.open('rb') as source:
        checksum = hashlib.file_digest(source, 'sha256').hexdigest()
    payload, control = temporary / 'payload', temporary / 'control'
    payload.mkdir(); control.mkdir()
    if kind == 'deb':
        for option, directory in (('--fsys-tarfile', payload), ('--ctrl-tarfile', control)):
            tar = temporary / 'members.tar'
            with tar.open('wb') as output:
                execute(['dpkg-deb', option, str(archive)], root, env, stdout=output)
            extract_tar(tar, directory)
        require((control / 'postinst').is_file(), 'missing_install_script')
    else:
        execute(['rpmkeys', '--checksig', '--nosignature', str(archive)], root, env, stdout=subprocess.PIPE)
        cpio = temporary / 'members.cpio'
        with cpio.open('wb') as output:
            execute(['rpm2cpio', str(archive)], root, env, stdout=output)
        extract_cpio(cpio, payload)
        scripts = execute(['rpm', '-qp', '--scripts', str(archive)], root, env, stdout=subprocess.PIPE).stdout
        require(b'postinstall' in scripts, 'missing_install_script')
        (control / 'scriptlets.sh').write_bytes(scripts)
    agent = payload / 'opt/fwcloud/agent'
    require((agent / '.env').is_file() and (agent / 'configure-api-key.sh').is_file()
            and any(agent.glob('plugins/**/*.sh')), 'incomplete_package_scope')
    require(not any(temporary.rglob('.gitleaksignore')), 'forbidden_ignore_file')
    # Scan extracted payload and installation scripts, not intermediate archive copies.
    (temporary / ('members.tar' if kind == 'deb' else 'members.cpio')).unlink()
    return checksum


def report_dir(root, kind):
    return root / ('reports/secrets' if kind == 'history' else f'reports/secrets-{kind}')


def prepare(root, kind):
    require(not (root / 'reports').is_symlink(), 'unsafe_report_directory')
    directory = report_dir(root, kind)
    if directory.is_symlink():
        directory.unlink()
    elif directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, mode=0o700)


def scan(root, env, kind):
    fields = {'scope': 'distribution' if kind != 'history' else '', 'package_type': kind if kind != 'history' else ''}
    code = 2
    try:
        policy(root, env)
        binary = Path(env['GITLEAKS_BINARY'])
        verify_version(binary, env)
        with tempfile.TemporaryDirectory(prefix='agent-secret-scan-', dir=env['RUNNER_TEMP']) as tmp:
            temporary = Path(tmp)
            ignore = temporary / 'empty.ignore'; ignore.touch()
            config = temporary / 'policy.toml'
            config.write_text((root / '.gitleaks.toml').read_text())
            if kind == 'history':
                fields.update(scope(root, env, json.loads(Path(env['GITHUB_EVENT_PATH']).read_text())))
                command = ['git', f"--log-opts=--text --no-ext-diff --no-textconv --diff-merges=first-parent {fields['log_opts']}"]
                target = root
            else:
                target = temporary / 'extracted'; target.mkdir()
                fields['package_sha256'] = package(root, env, kind, target)
                command = ['dir']
            report = report_dir(root, kind) / 'gitleaks.json'
            result = subprocess.run([str(binary), *command, '--config', str(config),
                '--gitleaks-ignore-path', str(ignore), '--ignore-gitleaks-allow', '--redact=100',
                '--report-format=json', '--report-path', str(report), '--timeout=300',
                '--log-level=error', '--no-banner', '--no-color', str(target)],
                cwd=root, env=environment(env), capture_output=True, timeout=330)
            code = result.returncode if result.returncode >= 0 else 128 - result.returncode
            fields.update(exit_code=str(code), log_bytes=str(len(result.stdout) + len(result.stderr)))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        # Paths, subprocess errors, malformed JSON and source content are never logged.
        print('Secret scan could not complete.', file=sys.stderr)
    finally:
        with Path(env['GITHUB_OUTPUT']).open('a') as output:
            for key, value in fields.items():
                output.write(f'{key}={value}\n')
    return code


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['install', 'prepare', 'scan', 'cleanup'])
    parser.add_argument('kind', nargs='?', choices=['history', 'deb', 'rpm'], default='history')
    args = parser.parse_args()
    try:
        if args.command == 'install':
            install(os.environ)
        elif args.command == 'prepare':
            prepare(ROOT, args.kind)
        elif args.command == 'cleanup':
            (report_dir(ROOT, args.kind) / 'gitleaks.json').unlink(missing_ok=True)
        else:
            return scan(ROOT, os.environ, args.kind)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        print('Secret scan setup or cleanup failed.', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
