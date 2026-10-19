#!/usr/bin/env python3
"""One bounded JSON request over an authenticated SSH forced-command channel.

Only prepare-recover for a live pending v1 output is reachable. Never broadcasts.
Configuration, native binary and public state must be administrator controlled.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import syslog

from watchtower import Native, WatchError, guard, point, txid, validate_recovery

PROTOCOL = 'icp-recovery-ssh-v1'
PROBE_PROTOCOL = 'icp-recovery-ssh-health-v1'
MAX_REQUEST = 1024
MAX_RESPONSE = 128 * 1024


def digest(descriptor):
    return hashlib.sha256(json.dumps(descriptor, sort_keys=True).encode()).hexdigest()


def outpoint(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}:0', value):
        raise WatchError('Expected pending TXID:0')
    return value


def pinned(descriptor, expected):
    txid(expected)
    if descriptor.get('version') != 'protected-v1' or descriptor.get('network') != 'testnet-10' or digest(descriptor) != expected:
        raise WatchError('Protected descriptor pin mismatch')


def request(value, expected):
    if not isinstance(value, dict) or set(value) != {'protocol', 'descriptor_sha256', 'pending'}:
        raise WatchError('Unexpected recovery request fields')
    if value['protocol'] != PROTOCOL or value['descriptor_sha256'] != expected:
        raise WatchError('Recovery protocol or descriptor mismatch')
    return outpoint(value['pending'])


def serve(value, config, native):
    probe = isinstance(value, dict) and set(value) == {'protocol', 'descriptor_sha256'} and value.get('protocol') == PROBE_PROTOCOL and value.get('descriptor_sha256') == config['descriptor_sha256']
    pending = None if probe else request(value, config['descriptor_sha256'])
    descriptor = native.call('descriptor')
    pinned(descriptor, config['descriptor_sha256'])
    snapshot = native.snapshot()  # independent node + exact pending UTXO, no key
    guard(snapshot['node'])
    if probe:
        return {'protocol': PROBE_PROTOCOL, 'descriptor_sha256': config['descriptor_sha256'], 'ready': True}
    live = {point(u['outpoint']): u['utxoEntry'] for u in snapshot['utxos']}
    entry = live.get(pending)
    if not entry or entry['scriptPublicKey'] != descriptor['pending_spk'] or entry.get('covenantId') is not None:
        raise WatchError('Requested outpoint is not a live pinned pending output')
    payload = native.prepare(pending)
    if payload.get('version') != 'protected-v1' or payload.get('network') != 'testnet-10' or payload.get('status') != 'PREPARED':
        raise WatchError('Unexpected native receipt')
    validate_recovery(payload, pending, entry['amount'], descriptor)
    # Local receipt paths and node metadata have no place in the wire protocol.
    return {k: payload[k] for k in ('version', 'network', 'status', 'id', 'transaction')}


class SignerNative(Native):
    def __init__(self, config):
        self.config = config
        super().__init__([config['cli']])

    def call(self, *args, json_output=True):
        if not args or args[0] not in ('descriptor', 'status', 'prepare-recover'):
            raise WatchError('Recovery signer operation forbidden')
        env = {'PATH': '/usr/bin:/bin', 'ICP_PROTECTED_STATE_DIR': self.config['state_dir'],
               'ICP_RPC_URL': self.config['rpc_url'],
               'ICP_PROTECTED_RECEIPT_DIR': self.config['receipt_dir']}
        if args[0] == 'prepare-recover':
            env['ICP_SIGNER_KEY_FILE'] = self.config['recovery_key']
        result = subprocess.run(self.command + list(args), cwd=self.config['working_dir'],
                                env=env, capture_output=True, text=True, timeout=35)
        if result.returncode:
            raise WatchError('Signer native operation failed')
        if len(result.stdout.encode()) > MAX_RESPONSE:
            raise WatchError('Signer response too large')
        return json.loads(result.stdout)


def server_config(path):
    value = json.loads(Path(path).read_text())
    fields = {'cli', 'state_dir', 'rpc_url', 'recovery_key', 'working_dir', 'receipt_dir', 'descriptor_sha256'}
    if set(value) != fields or not all(isinstance(v, str) for v in value.values()):
        raise WatchError('Invalid signer configuration')
    for k in ('cli', 'state_dir', 'recovery_key', 'working_dir', 'receipt_dir'):
        if not Path(value[k]).is_absolute():
            raise WatchError('Signer paths must be absolute')
    txid(value['descriptor_sha256'])
    if not value['rpc_url'].startswith(('wss://', 'ws://127.0.0.1:')):
        raise WatchError('Use TLS RPC or a local node')
    return value


class RemoteNative(Native):
    """Public local native operations; recovery signing only over pinned SSH."""
    def __init__(self, command, config_path, descriptor):
        super().__init__(command)
        self.remote = json.loads(Path(config_path).read_text())
        c = self.remote
        if set(c) != {'host', 'user', 'port', 'identity_file', 'known_hosts_file', 'descriptor_sha256'}:
            raise WatchError('Invalid SSH signer configuration')
        if not isinstance(c['host'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', c['host']):
            raise WatchError('Invalid signer host')
        if not isinstance(c['user'], str) or not re.fullmatch(r'[a-z_][a-z0-9_-]*', c['user']):
            raise WatchError('Invalid signer account')
        if type(c['port']) is not int or not 1 <= c['port'] <= 65535:
            raise WatchError('Invalid signer port')
        for k in ('identity_file', 'known_hosts_file'):
            if not isinstance(c[k], str) or not Path(c[k]).is_absolute() or not Path(c[k]).is_file():
                raise WatchError('SSH identity and known-hosts files must exist at absolute paths')
        pinned(descriptor, c['descriptor_sha256'])

    def prepare(self, pending):
        c = self.remote
        message = {'protocol': PROTOCOL, 'descriptor_sha256': c['descriptor_sha256'], 'pending': outpoint(pending)}
        payload = self.exchange(message)
        if payload.get('version') != 'protected-v1' or payload.get('network') != 'testnet-10' or payload.get('status') != 'PREPARED':
            raise WatchError('Unexpected remote receipt')
        return payload

    def probe(self):
        expected = {'protocol': PROBE_PROTOCOL, 'descriptor_sha256': self.remote['descriptor_sha256'], 'ready': True}
        result = self.exchange({k: expected[k] for k in ('protocol', 'descriptor_sha256')}, timeout=40)
        if result != expected:
            raise WatchError('Unexpected remote readiness response')

    def exchange(self, message, timeout=90):
        c = self.remote
        # Ignore user SSH config, agents, proxy commands, global hosts and TOFU.
        command = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', str(c['port']),
                   '-l', c['user'], '-i', c['identity_file'],
                   '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
                   '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
                   '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'UserKnownHostsFile=' + c['known_hosts_file'],
                   '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no',
                   '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                   c['host']]
        env = {k: v for k, v in os.environ.items() if k not in ('ICP_SIGNER_KEY_FILE', 'SSH_AUTH_SOCK')}
        result = subprocess.run(command, input=json.dumps(message), capture_output=True, text=True,
                                timeout=timeout, env=env)
        if result.returncode or len(result.stdout.encode()) > MAX_RESPONSE:
            raise WatchError('Remote recovery signing failed; inspect signer journal')
        return json.loads(result.stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True, type=Path)
    a = p.parse_args()
    syslog.openlog('icp-recovery', syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    try:
        config = server_config(a.config)
        # A remote command, subsystem or arbitrary argument is never interpreted.
        if os.environ.get('SSH_ORIGINAL_COMMAND', ''):
            raise WatchError('Remote commands are forbidden')
        raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if len(raw) > MAX_REQUEST:
            raise WatchError('Recovery request too large')
        result = serve(json.loads(raw), config, SignerNative(config))
        event = {'kind': 'RECOVERY_PREPARED', 'id': result['id']} if 'id' in result else {'kind': 'SIGNER_READY'}
        syslog.syslog(syslog.LOG_INFO, json.dumps(event))
        print(json.dumps(result), flush=True)
    except Exception:
        # Avoid sending key paths, subprocess diagnostics or configuration back.
        syslog.syslog(syslog.LOG_WARNING, 'RECOVERY_REQUEST_REFUSED')
        print('Recovery request refused', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
