#!/usr/bin/env python3
"""Probe signer independently, so a slow signer cannot block chain monitoring."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time

from recovery_signer import RemoteNative, digest


def probe(client, database, descriptor, now=None):
    with sqlite3.connect(Path(database).resolve().as_uri() + '?mode=rw', uri=True, timeout=1) as db:
        row = db.execute("SELECT v FROM meta WHERE k='config'").fetchone()
        if not row or row[0] != digest(descriptor):
            raise RuntimeError('Probe descriptor differs from watcher database')
    error = ''
    try:
        client.probe()
    except Exception:
        error = 'Remote signer readiness check failed'
    # Timestamp completion, with a bounded 40-second probe and independent timer.
    at = time.time() if now is None else now
    with sqlite3.connect(Path(database).resolve().as_uri() + '?mode=rw', uri=True, timeout=1) as db:
        with db:
            db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', ('signer_probe_error', error))
            db.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', ('signer_probe_at', str(at)))
    return not error


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--descriptor', type=Path, required=True)
    p.add_argument('--db', type=Path, required=True)
    a = p.parse_args()
    try:
        descriptor = json.loads(a.descriptor.read_text())
        ready = probe(RemoteNative(['/unused'], a.config, descriptor), a.db, descriptor)
    except Exception:
        ready = False
    print(json.dumps({'signer_ready': ready}), flush=True)
    return 0 if ready else 1


if __name__ == '__main__':
    sys.exit(main())
