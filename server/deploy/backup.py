#!/usr/bin/python3
import datetime
import os
import pathlib
import sqlite3

os.umask(0o077)
root = pathlib.Path('/var/backups/yaoxi-accounts')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
name = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
with sqlite3.connect('file:/var/lib/yaoxi-accounts/accounts.sqlite?mode=ro', uri=True) as source:
    with sqlite3.connect(root / (name + '.sqlite')) as target:
        source.backup(target)
        if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Backup integrity check failed')
for old in sorted(root.glob('*.sqlite'))[:-14]:
    old.unlink()
print('Account database backup verified')
