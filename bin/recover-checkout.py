#!/usr/bin/env python3
"""Recover a permission-interrupted deployment checkout without stashing runtime data."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import subprocess
import sys

CODE_DIRS = ('.git', '.github', 'bin', 'relay', 'signer', 'postgres', 'tests', 'ui')
CODE_FILES = ('.dockerignore', '.env.example', '.gitignore', 'CHANGELOG.md', 'README.md',
              'backup.sh', 'docker-compose.yml', 'Dockerfile', 'docker-entrypoint.sh', 'LICENSE')
RUNTIME_CONFIGS = ('server.conf', 'config/client.conf', 'config/easy-rsa.vars', 'fw-rules.sh')
RECOVERY_PREFIX = 'openvpn-checkout-recovery-'


class RecoveryError(Exception):
    pass


class Recovery:
    def __init__(self, root: Path, repair_permissions=False):
        self.root = root.resolve()
        self.repair_permissions = repair_permissions
        self.backup = None

    def command(self, *args, data=None):
        result = subprocess.run(args, cwd=self.root, input=data, capture_output=True)
        if result.returncode:
            # Never print file contents, patches, credentials or an authenticated remote URL.
            if self.backup:
                self.private_copy('command-error-' + secrets.token_hex(3) + '.txt', result.stderr)
            action = args[0] + (' ' + args[1] if args[0] == 'git' and len(args) > 1 else '')
            raise RecoveryError(f'{action} failed (exit {result.returncode}); recovery stopped, saved state retained')
        return result.stdout

    def git(self, *args):
        return self.command('git', *args)

    def text(self, *args):
        return self.git(*args).decode().strip()

    def blob(self, ref, name):
        result = subprocess.run(['git', 'show', f'{ref}:{name}'], cwd=self.root, capture_output=True)
        return result.stdout if result.returncode == 0 else None

    def private_copy(self, name, data):
        path = self.backup / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)

    @staticmethod
    def is_code(name):
        return name in CODE_FILES or any(name.startswith(folder + '/') for folder in CODE_DIRS if folder != '.git')

    def prepare(self):
        if not (self.root / '.git').is_dir() or (self.root / '.git').is_symlink():
            raise RecoveryError('Expected a regular deployment checkout with a .git directory')
        if self.repair_permissions:
            if os.geteuid() == 0:
                raise RecoveryError('Run this helper as your normal login user; it invokes sudo only where needed')
            paths = [name for name in (*CODE_DIRS, *CODE_FILES) if (self.root / name).exists()]
            if any((self.root / name).is_symlink() for name in paths):
                raise RecoveryError('A code path is a symlink; refusing automatic ownership changes')
            owner = f'{os.getuid()}:{os.getgid()}'
            self.command('sudo', 'chown', '-h', owner, '--', str(self.root))
            # No recursive operation on the repository root or runtime directories.
            self.command('sudo', 'chown', '-hR', owner, '--', *paths)
            print('Code and Git ownership repaired; runtime directories and credentials were not reowned.', flush=True)
        if self.text('branch', '--show-current') != 'main':
            raise RecoveryError('Expected branch main; switch or review the current branch first')
        for name in ('MERGE_HEAD', 'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'rebase-merge', 'rebase-apply'):
            if (self.root / '.git' / name).exists():
                raise RecoveryError('A Git operation is in progress; resolve it before checkout recovery')
        folder = self.root / '.git' / 'openvpn-recovery'
        folder.mkdir(mode=0o700, exist_ok=True)
        folder.chmod(0o700)
        self.backup = folder / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(3))
        self.backup.mkdir(mode=0o700)

    def read_runtime(self, name):
        path = self.root / name
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != self.root and self.root in parent.parents):
            raise RecoveryError(f'{name}: symlinked runtime configuration needs manual review')
        try:
            return path.read_bytes() if path.exists() else None
        except PermissionError:
            if not self.repair_permissions:
                raise RecoveryError(f'{name}: read access requires --repair-permissions') from None
            return self.command('sudo', 'cat', '--', str(path))

    def runtime_plan(self, original_stash, target):
        plan = {}
        if not original_stash:
            return plan
        for name in (*RUNTIME_CONFIGS, 'docker-compose.yml'):
            base = self.blob(original_stash + '^1', name)
            saved = self.blob(original_stash, name)
            if saved == base:
                continue
            if saved is not None:
                self.private_copy('previous-stash/' + name, saved)
            if name == 'docker-compose.yml':
                if saved not in (base, self.blob(target, name)):
                    raise RecoveryError('The previous stash contains custom Compose settings. Review the private saved copy before updating')
                continue  # Never replace the new PostgreSQL Compose with an older one.
            current = self.read_runtime(name)
            if current is not None:
                self.private_copy('working-config/' + name, current)
            if current == saved:
                continue
            if base is None or saved is None or current != base or self.blob(target, name) not in (base, saved):
                raise RecoveryError(f'{name}: independent configuration changes need review; neither copy was overwritten')
            plan[name] = saved
        return plan

    def restore_runtime(self, plan):
        for name, data in plan.items():
            # Write in place so live container bind mounts retain the same inode.
            path = self.root / name
            try:
                with path.open('wb') as stream:
                    stream.write(data)
            except PermissionError:
                if not self.repair_permissions:
                    raise RecoveryError(f'{name}: write access requires --repair-permissions') from None
                self.command('sudo', 'tee', '--', str(path), data=data)
            print(f'Restored {name} from the previous stash.', flush=True)

    def run(self):
        self.prepare()
        old_head = self.text('rev-parse', 'HEAD')
        stashes = self.text('stash', 'list', '--format=%H %gs').splitlines()
        # Our code-only recovery stashes are not a source of older runtime config.
        original_stash = next((row.split()[0] for row in stashes if RECOVERY_PREFIX not in row
                               and self.text('rev-parse', row.split()[0] + '^1') == old_head), None)
        self.private_copy('original-state.txt', (old_head + '\n' + '\n'.join(stashes) + '\n').encode())
        print('Fetching origin/main; existing stashes are retained.', flush=True)
        self.git('fetch', 'origin', 'main')
        target = self.text('rev-parse', 'refs/remotes/origin/main')
        self.git('merge-base', '--is-ancestor', old_head, target)
        plan = self.runtime_plan(original_stash, target)
        remote_files = set(self.git('ls-tree', '-r', '--name-only', '-z', target).decode().strip('\0').split('\0'))
        changed = self.git('diff', '--name-only', '-z', 'HEAD').decode().strip('\0').split('\0')
        untracked = self.git('ls-files', '--others', '--exclude-standard', '-z').decode().strip('\0').split('\0')
        # Stash tracked code changes and only incoming-code collisions. Do not
        # sweep untracked guests, keys, databases, backups or custom local files.
        paths = sorted({p for p in changed if p and self.is_code(p)} |
                       {p for p in untracked if p in remote_files and self.is_code(p)})
        if paths:
            self.git('stash', 'push', '--include-untracked', '-m', RECOVERY_PREFIX + self.backup.name, '--', *paths)
            self.private_copy('code-stash.txt', (self.text('rev-parse', 'refs/stash') + '\n').encode())
            print(f'Saved interrupted-checkout changes for {len(paths)} code paths in a new stash.', flush=True)
        self.git('merge', '--ff-only', target)
        self.restore_runtime(plan)
        print('Checkout updated to ' + self.text('rev-parse', '--short', 'HEAD'), flush=True)
        print('Recovery records: ' + str(self.backup), flush=True)
        print('Existing stashes were kept. Do not apply the entire old stash over the updated code.', flush=True)
        print('No containers were restarted. Next: bin/upgrade-relay.sh --sudo-docker', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--repair-permissions', action='store_true', help='Use sudo for code/Git ownership repair and protected configuration access')
    args = parser.parse_args()
    recovery = Recovery(args.repo, args.repair_permissions)
    try:
        recovery.run()
    except (OSError, RecoveryError) as exc:
        print(str(exc), file=sys.stderr)
        if recovery.backup:
            print('Saved recovery records: ' + str(recovery.backup), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
