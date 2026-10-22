#!/usr/bin/env python3
"""Fictional binary exchange with encrypted software keystores on ONE host."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import pq_locked_adapter as locked
from pq_recipient_file_exchange import relay_handoff


def demo():
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        # Fresh secrets for fictional keys, kept in this trusted test process only.
        passwords = {role: os.urandom(32).hex().encode() for role in locked.base.ROLES}
        calls = 0

        def cli(*arguments, role=None, password=None, succeeds=True):
            nonlocal calls
            calls += 1
            prefix = []
            descriptor = None
            if role is not None:
                descriptor, writer = os.pipe()
                try:
                    os.write(writer, passwords[role] if password is None else password)
                finally:
                    os.close(writer)
                prefix = ['--passphrase-fd', str(descriptor)]
            try:
                result = subprocess.run([sys.executable, str(ROOT / 'scripts/pq_locked_adapter.py'),
                                         *prefix, *map(str, arguments)], capture_output=True,
                                        pass_fds=() if descriptor is None else (descriptor,), timeout=20)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            if (result.returncode == 0) != succeeds:
                raise AssertionError('Unexpected locked endpoint result; output suppressed')
            return json.loads(result.stdout) if succeeds else None

        for role in locked.base.ROLES:
            cli('keygen', '--role', role, '--endpoint', folder / role,
                '--output', folder / f'{role}-public.json', role=role)
            if (folder / role / 'keys.json').exists():
                raise AssertionError('Plaintext key file appeared')
        pin = cli('policy', '--approver', folder / 'approver-public.json',
                  '--sender', folder / 'sender-public.json', '--recipient', folder / 'recipient-public.json',
                  '--output', folder / 'policy.json')['policy_id']
        common = ['--policy', folder / 'policy.json', '--policy-id', pin]

        def operation(name, role, output, *arguments, succeeds=True, password=None):
            return cli(name, *common, '--endpoint', folder / role, '--output', folder / output,
                       *arguments, role=role, succeeds=succeeds, password=password)

        operation('challenge', 'approver', 'challenge.json')
        operation('answer', 'recipient', 'proof.json', '--input', folder / 'challenge.json')
        operation('bind', 'approver', 'binding.json', '--input', folder / 'proof.json')
        plaintext = b'FICTIONAL LOCKED KEYSTORE BINARY\x00\xff\nNo real sensitive records.'
        locked.base.write_new(folder / 'input.bin', plaintext)
        operation('seal', 'sender', 'sealed.json', '--binding', folder / 'binding.json', '--input', folder / 'input.bin')
        operation('approve', 'approver', 'approved.json', '--input', folder / 'sealed.json')
        operation('send', 'sender', 'envelope.json', '--input', folder / 'approved.json')
        raw = (folder / 'envelope.json').read_bytes()
        if plaintext in raw:
            raise AssertionError('Plaintext appeared in envelope')
        locked.base.write_new(folder / 'transport.json', relay_handoff(raw))
        # Failed unlock must not consume the message or create acceptance state.
        operation('receive', 'recipient', 'wrong-password.bin', '--input', folder / 'transport.json',
                  '--receipt', folder / 'wrong-password-receipt.json', password=os.urandom(32).hex().encode(), succeeds=False)
        accepted = operation('receive', 'recipient', 'received.bin', '--input', folder / 'transport.json',
                             '--receipt', folder / 'receipt.json')
        if (folder / 'received.bin').read_bytes() != plaintext:
            raise AssertionError('Recipient bytes differ')
        cli('verify-receipt', *common, '--input', folder / 'envelope.json', '--receipt', folder / 'receipt.json')
        operation('receive', 'recipient', 'replayed.bin', '--input', folder / 'transport.json',
                  '--receipt', folder / 'replayed-receipt.json', succeeds=False)
        operation('receipt', 'recipient', 'recovered-receipt.json', '--transfer-id', accepted['transfer_id'])
        if (folder / 'recovered-receipt.json').read_bytes() != (folder / 'receipt.json').read_bytes():
            raise AssertionError('Recovered receipt differs')
        public = locked.base.read_json(folder / 'recipient-public.json')
        endpoint_pin = locked.endpoint_id(public)
        backup = folder / 'recipient.icp-key-backup'
        cli('backup-key', '--endpoint', folder / 'recipient', '--endpoint-id', endpoint_pin,
            '--output', backup, role='recipient')
        cli('check-backup', '--input', backup, '--endpoint-id', endpoint_pin, role='recipient')
        if backup.read_bytes() != (folder / 'recipient' / locked.KEY_FILE).read_bytes():
            raise AssertionError('Encrypted backup differs')
        return dict(mode=locked.lab.MODE, scenario='FICTIONAL_ENCRYPTED_KEYSTORE_ONE_HOST',
                    endpoint_processes=calls, ciphertext_relay_processes=1, plaintext_bytes=len(plaintext),
                    recipient_bytes_match=True, receipt_signature_verified=True,
                    receipt_recovered_after_unlock=True, replay_rejected_after_unlock=True,
                    wrong_password_rejected=True, encrypted_key_backup_verified=True,
                    plaintext_key_files_created=False, passwords_in_arguments=False,
                    endpoint_state_restored=False, hardware_isolation_tested=False,
                    network_scope='LOOPBACK_SINGLE_HOST', real_transactions=0)


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
