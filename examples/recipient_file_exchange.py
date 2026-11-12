#!/usr/bin/env python3
"""Fictional binary-file handoff using separate CLI processes on ONE host."""
import json
import hashlib
from http.client import HTTPConnection
from pathlib import Path
import select
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import recipient_adapter as adapter


def relay_handoff(raw):
    """A separate relay process receives ciphertext only, with no key arguments."""
    relay = subprocess.Popen([sys.executable, str(ROOT / 'examples/recipient_ciphertext_relay.py')],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        if not select.select([relay.stdout], [], [], 10)[0]:
            raise AssertionError('Loopback relay did not start')
        ready = json.loads(relay.stdout.readline())
        identifier = hashlib.sha256(raw).hexdigest()
        connection = HTTPConnection('127.0.0.1', ready['port'], timeout=5)
        try:
            connection.request('PUT', '/envelope/' + identifier, body=raw)
            response = connection.getresponse()
            if response.status != 201:
                raise AssertionError('Ciphertext upload failed')
            response.read()
            connection.request('GET', '/envelope/' + identifier)
            response = connection.getresponse()
            received = response.read(adapter.lab.MAX_WIRE + 1)
            if response.status != 200 or received != raw:
                raise AssertionError('Ciphertext transport changed bytes')
            return received
        finally:
            connection.close()
    finally:
        relay.terminate()
        try:
            relay.wait(timeout=5)
        except subprocess.TimeoutExpired:
            relay.kill()
            relay.wait(timeout=5)
        relay.stdout.close()


def demo():
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        calls = 0

        def cli(*arguments, succeeds=True):
            nonlocal calls
            calls += 1
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/recipient_adapter.py'),
                                     *map(str, arguments)], capture_output=True, timeout=15)
            if (result.returncode == 0) != succeeds:
                raise AssertionError('Unexpected endpoint command result; output suppressed')
            return json.loads(result.stdout) if succeeds else None

        for role in adapter.ROLES:
            cli('keygen', '--role', role, '--endpoint', folder / role,
                '--output', folder / f'{role}-public.json')
        pin = cli('policy', '--approver', folder / 'approver-public.json',
                  '--sender', folder / 'sender-public.json', '--recipient', folder / 'recipient-public.json',
                  '--output', folder / 'policy.json')['policy_id']
        common = ['--policy', folder / 'policy.json', '--policy-id', pin]

        def operation(name, role, output, *arguments, succeeds=True):
            return cli(name, *common, '--endpoint', folder / role, '--output', folder / output,
                       *arguments, succeeds=succeeds)

        operation('challenge', 'approver', 'challenge.json')
        operation('answer', 'recipient', 'proof.json', '--input', folder / 'challenge.json')
        operation('bind', 'approver', 'binding.json', '--input', folder / 'proof.json')
        plaintext = b'FICTIONAL BINARY FILE ONLY\x00\xff\nNo agency, wallet or real sensitive record.'
        adapter.write_new(folder / 'input.bin', plaintext)
        operation('seal', 'sender', 'sealed.json', '--binding', folder / 'binding.json',
                  '--input', folder / 'input.bin')
        operation('approve', 'approver', 'approved.json', '--input', folder / 'sealed.json')
        operation('send', 'sender', 'envelope.json', '--input', folder / 'approved.json')
        wire = (folder / 'envelope.json').read_bytes()
        if plaintext in wire:
            raise AssertionError('Plaintext appeared in envelope')
        # The relay process has no key paths; HTTP carries only the ciphertext.
        adapter.write_new(folder / 'transport-copy.json', relay_handoff(wire))
        accepted = operation('receive', 'recipient', 'received.bin', '--input', folder / 'transport-copy.json',
                             '--receipt', folder / 'receipt.json')
        if (folder / 'received.bin').read_bytes() != plaintext:
            raise AssertionError('Recipient bytes differ')
        cli('verify-receipt', *common, '--input', folder / 'envelope.json', '--receipt', folder / 'receipt.json')
        operation('receive', 'recipient', 'replayed.bin', '--input', folder / 'transport-copy.json',
                  '--receipt', folder / 'replayed-receipt.json', succeeds=False)
        operation('receive', 'sender', 'wrong-role.bin', '--input', folder / 'transport-copy.json',
                  '--receipt', folder / 'wrong-role-receipt.json', succeeds=False)
        operation('receipt', 'recipient', 'recovered-receipt.json', '--transfer-id', accepted['transfer_id'])
        if (folder / 'recovered-receipt.json').read_bytes() != (folder / 'receipt.json').read_bytes():
            raise AssertionError('Recovered receipt differs')
        return dict(mode=adapter.lab.MODE, scenario='FICTIONAL_BINARY_FILE_SEPARATE_PROCESSES_ONE_HOST',
                    endpoint_processes=calls, plaintext_bytes=len(plaintext), recipient_bytes_match=True,
                    envelope_excludes_plaintext=True, replay_rejected=True, wrong_role_rejected=True,
                    receipt_signature_verified=True, receipt_recovered_after_restart=True,
                    private_keys_exchanged=False, real_transactions=0, network_delivery_tested=True,
                    network_scope='LOOPBACK_SINGLE_HOST', ciphertext_relay_processes=1,
                    independent_host_isolation_tested=False)


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
