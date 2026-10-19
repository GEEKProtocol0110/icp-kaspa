#!/usr/bin/env python3
"""Read-only watcher health check; JSON and nonzero exit on degraded custody monitoring."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time


def health(path, max_age=15, max_stall=30, now=None, require_remote=True):
    now = time.time() if now is None else now
    with sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=1) as db:
        db.row_factory = sqlite3.Row
        meta = dict(db.execute('SELECT k,v FROM meta'))
        beat = json.loads(meta.get('heartbeat', '{}'))
        state = json.loads(meta.get('state', '{}'))
        issues = []
        if not meta.get('tip'):
            issues.append('UNARMED')
        if not beat or not 0 <= now - beat['at'] <= max_age:
            issues.append('STALE_HEARTBEAT')
        if beat and not 0 <= now - beat['advanced_at'] <= max_stall:
            issues.append('NODE_DAA_STALLED')
        if not beat.get('execute'):
            issues.append('DRY_RUN')
        if require_remote and not beat.get('remote_signer'):
            issues.append('LOCAL_SIGNER')
        if require_remote and (meta.get('signer_probe_error') or not 0 <= now-float(meta.get('signer_probe_at', 0)) <= 120):
            issues.append('SIGNER_UNAVAILABLE')
        if meta.get('health_error'):
            issues.append('WATCH_ERROR')
        progress = json.loads(meta.get('scan_progress', '{}'))
        if progress and (progress.get('remaining_blocks', 0) or not progress.get('target_reached')):
            issues.append('CHAIN_BACKLOG')
        if any(t.get('kind') == 'UNAUTHORIZED_EXECUTION' for t in state.get('terminal', {}).values()):
            issues.append('UNAUTHORIZED_EXECUTION')
        outputs = state.get('outputs', {})
        quarantined = {k: v for k, v in outputs.items() if v.get('stage') == 'quarantined'}
        for root, terminal in state.get('terminal', {}).items():
            if terminal.get('custody') == 'QUARANTINED':
                output = quarantined.get(terminal.get('outpoint'), {})
                if output.get('root') != root or output.get('amount') != terminal.get('amount'):
                    issues.append('QUARANTINE_TRACKING_INCOMPLETE')
        for outpoint, output in quarantined.items():
            terminal = state.get('terminal', {}).get(output['root'], {})
            if terminal.get('custody') != 'QUARANTINED' or terminal.get('outpoint') != outpoint:
                issues.append('QUARANTINE_TRACKING_INCOMPLETE')
        actions = {r['pending']: r for r in db.execute('SELECT pending,status,attempts,error FROM actions')}
        for pending, output in state.get('outputs', {}).items():
            if output['stage'] != 'pending' or output['authorized']:
                continue
            row = actions.get(pending)
            issues.append('RECOVERY_UNCONFIRMED')
            if row and row['attempts'] >= 3:
                issues.append('RECOVERY_ATTEMPTS_EXHAUSTED')
            if row and row['error']:
                issues.append('RECOVERY_RETRY_REQUIRED')
            if beat.get('daa', 0) >= output['accepted_daa'] + json.loads(meta.get('health_limits', '{}')).get('delay_daa', 0):
                issues.append('RECOVERY_DEADLINE_REACHED')
        return {'healthy': not issues, 'issues': sorted(set(issues)),
                'heartbeat': beat, 'tip': meta.get('tip'), 'scan_progress': progress,
                'custody': {'quarantined_outputs': len(quarantined),
                            'cold_releases_observed': sum(t.get('custody') == 'COLD_RELEASED'
                                                         for t in state.get('terminal', {}).values())}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db', type=Path, required=True)
    p.add_argument('--max-age', type=float, default=15)
    p.add_argument('--max-stall', type=float, default=30)
    p.add_argument('--allow-local', action='store_true', help='Testing only')
    a = p.parse_args()
    if a.max_age <= 0 or a.max_stall <= 0:
        p.error('Health intervals must be positive')
    try:
        report = health(a.db, a.max_age, a.max_stall, require_remote=not a.allow_local)
    except Exception:
        report = {'healthy': False, 'issues': ['HEALTH_STATE_UNREADABLE']}
    print(json.dumps(report), flush=True)
    return 0 if report['healthy'] else 1


if __name__ == '__main__':
    sys.exit(main())
