"""Encrypted experimental software key storage; temporary keys and fictional data."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import pq_locked_adapter as app

PASSWORD = b'fictional test passphrase only 7345'


class LockedEndpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.endpoint = app.LockedEndpoint.create(self.root / 'recipient', 'recipient', PASSWORD)
        self.keyfile = self.endpoint.path / app.KEY_FILE
        self.raw = self.keyfile.read_bytes()
        self.pin = app.endpoint_id(self.endpoint.public())

    def change_store(self, mutate):
        body = json.loads(self.raw)
        mutate(body)
        self.keyfile.write_bytes(app.lab.canonical(body))

    def prepared_transfer(self):
        approver = app.LockedEndpoint.create(self.root / 'approver', 'approver', PASSWORD)
        sender = app.LockedEndpoint.create(self.root / 'sender', 'sender', PASSWORD)
        policy = app.base.make_policy(approver.public(), sender.public(), self.endpoint.public())
        challenge = approver.challenge(policy, 100)
        binding = approver.bind(policy, self.endpoint.answer(policy, challenge, 101), 102)
        envelope = sender.send(policy, approver.approve(policy,
            sender.seal(policy, binding, b'fictional recovery sample', 103), 104), 105)
        return policy, app.lab.canonical(envelope)

    def test_keys_are_encrypted_at_rest_and_unlock_preserves_identity(self):
        self.assertEqual(app.LockedEndpoint(self.endpoint.path, PASSWORD).public(), self.endpoint.public())
        self.assertNotIn(self.endpoint.identity.private_bytes_raw().hex().encode(), self.raw)
        self.assertNotIn(self.endpoint.delivery.private_bytes_raw().hex().encode(), self.raw)
        self.assertNotIn(PASSWORD, self.raw)
        self.assertFalse((self.endpoint.path / 'keys.json').exists())
        self.assertEqual(self.keyfile.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.endpoint.path.stat().st_mode & 0o777, 0o700)

    def test_all_three_roles_roundtrip_without_recipient_secret_in_other_roles(self):
        for role in ('sender', 'approver'):
            endpoint = app.LockedEndpoint.create(self.root / role, role, PASSWORD)
            reopened = app.LockedEndpoint(endpoint.path, PASSWORD)
            self.assertEqual(endpoint.public(), reopened.public())
            self.assertIsNone(reopened.delivery)

    def test_wrong_password_rejects_without_modification_or_state_creation(self):
        with self.assertRaises(ValueError): app.LockedEndpoint(self.endpoint.path, b'wrong fictional password 1234')
        self.assertEqual(self.keyfile.read_bytes(), self.raw)
        self.assertEqual(list(self.endpoint.path.iterdir()), [self.keyfile])

    def test_changed_ciphertext_rejected(self):
        self.change_store(lambda b: b.update(ciphertext=b['ciphertext'][:-2] + ('00' if b['ciphertext'][-2:] != '00' else '01')))
        with self.assertRaises(ValueError): app.LockedEndpoint(self.endpoint.path, PASSWORD)

    def test_nonce_salt_or_endpoint_binding_tamper_rejected(self):
        for field, size in (('nonce', 12), ('salt', 16), ('endpoint_id', 48)):
            body = json.loads(self.raw); body[field] = '00' * size
            with self.assertRaises(ValueError): app.unlock(app.lab.canonical(body), PASSWORD)

    def test_profiles_and_expensive_kdf_parameters_reject_before_derivation(self):
        for field, value in (('format', 'old'), ('suite', 'classical'), ('aead', 'AES-128-GCM'),
                             ('kdf', dict(app.KDF, memory_kib=2 ** 40)), ('kdf', dict(app.KDF, iterations=1)),
                             ('kdf', dict(app.KDF, extra=1))):
            body = dict(json.loads(self.raw), **{field: value})
            with patch.object(app, 'derive') as derive:
                with self.assertRaises(ValueError): app.unlock(app.lab.canonical(body), PASSWORD)
                derive.assert_not_called()

    def test_oversize_and_bad_ciphertext_reject_before_derivation(self):
        for raw in (b' ' * (app.MAX_STORE + 1), app.lab.canonical(dict(json.loads(self.raw), ciphertext='ff' * 5000)),
                    app.lab.canonical(dict(json.loads(self.raw), ciphertext='xyz'))):
            with patch.object(app, 'derive') as derive:
                with self.assertRaises(ValueError): app.unlock(raw, PASSWORD)
                derive.assert_not_called()

    def test_duplicate_fields_reject(self):
        raw = self.raw[:-1] + b',"format":"duplicate"}'
        with self.assertRaises(ValueError): app.unlock(raw, PASSWORD)

    def test_unknown_missing_fields_and_truncation_reject(self):
        body = json.loads(self.raw)
        missing = dict(body); del missing['salt']
        for raw in (app.lab.canonical(dict(body, extra=True)), app.lab.canonical(missing), self.raw[:-5]):
            with self.assertRaises(ValueError): app.unlock(raw, PASSWORD)

    def test_fixed_password_limits(self):
        for password in (b'', b'short', b' ' * 20, b'a' * 1025, b'a' * 16 + b'\n', b'a' * 16 + b'\0', 'not bytes at all'):
            with self.assertRaises(ValueError): app.LockedEndpoint.create(self.root / 'invalid', 'sender', password)
            self.assertFalse((self.root / 'invalid').exists())
        for size in (16, 1024): self.assertEqual(len(app.password_bytes(b'x' * size)), size)

    def test_new_salt_and_nonce_for_same_keys_and_password(self):
        keys = app.unlock(self.raw, PASSWORD)
        again = app.protect(keys, PASSWORD)
        first, second = json.loads(self.raw), json.loads(again)
        self.assertNotEqual(first['salt'], second['salt'])
        self.assertNotEqual(first['nonce'], second['nonce'])
        self.assertNotEqual(first['ciphertext'], second['ciphertext'])
        self.assertEqual(app.unlock(again, PASSWORD), keys)

    def test_public_pin_required_to_check_exact_backup(self):
        self.assertEqual(app.public_keys(app.unlock(self.raw, PASSWORD, self.pin)), self.endpoint.public())
        with patch.object(app, 'derive') as derive:
            with self.assertRaises(ValueError): app.unlock(self.raw, PASSWORD, '00' * 48)
            derive.assert_not_called()

    def test_backup_is_encrypted_private_and_never_replaces(self):
        output = self.root / 'keys.icp-key-backup'
        self.endpoint.backup_key(output, PASSWORD, self.pin)
        self.assertEqual(output.read_bytes(), self.raw)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): self.endpoint.backup_key(output, PASSWORD, self.pin)
        self.assertEqual(output.read_bytes(), self.raw)

    def test_backup_with_wrong_password_or_pin_writes_nothing(self):
        output = self.root / 'failed.icp-key-backup'
        for password, pin in ((b'wrong fictional password', self.pin), (PASSWORD, '00' * 48)):
            with self.assertRaises(ValueError): self.endpoint.backup_key(output, password, pin)
            self.assertFalse(output.exists())

    def test_backup_rejects_replaced_endpoint(self):
        other = app.LockedEndpoint.create(self.root / 'other', 'recipient', PASSWORD)
        self.keyfile.write_bytes((other.path / app.KEY_FILE).read_bytes())
        with self.assertRaises(ValueError): self.endpoint.backup_key(self.root / 'bad.icp-key-backup', PASSWORD,
                                                                   app.endpoint_id(other.public()))

    def test_keystore_permissions_and_symlinks_rejected(self):
        self.keyfile.chmod(0o644)
        with self.assertRaises(ValueError): app.LockedEndpoint(self.endpoint.path, PASSWORD)
        self.keyfile.chmod(0o600)
        link = self.root / 'link'; link.symlink_to(self.endpoint.path, target_is_directory=True)
        with self.assertRaises(ValueError): app.LockedEndpoint(link, PASSWORD)
        self.keyfile.rename(self.root / 'saved')
        self.keyfile.symlink_to(self.root / 'saved')
        with self.assertRaises(OSError): app.LockedEndpoint(self.endpoint.path, PASSWORD)

    def test_fifo_key_file_rejected_without_blocking(self):
        self.keyfile.unlink(); os.mkfifo(self.keyfile, 0o600)
        with self.assertRaises(ValueError): app.LockedEndpoint(self.endpoint.path, PASSWORD)

    def test_plaintext_and_locked_endpoints_never_migrate_implicitly(self):
        old = app.base.Endpoint.create(self.root / 'plain', 'recipient')
        with self.assertRaises(ValueError): app.LockedEndpoint(old.path, PASSWORD)
        with self.assertRaises(OSError): app.base.Endpoint(self.endpoint.path)
        (self.endpoint.path / 'keys.json').write_text('{}')
        with self.assertRaises(ValueError): app.LockedEndpoint(self.endpoint.path, PASSWORD)

    def test_keygen_existing_directory_and_failure_do_not_write_clear_keys(self):
        with self.assertRaises(FileExistsError): app.LockedEndpoint.create(self.endpoint.path, 'recipient', PASSWORD)
        self.assertEqual(self.keyfile.read_bytes(), self.raw)
        with patch.object(app.base, 'write_new', side_effect=OSError('simulated')):
            with self.assertRaises(OSError): app.LockedEndpoint.create(self.root / 'failed', 'sender', PASSWORD)
        self.assertEqual(list((self.root / 'failed').iterdir()), [])

    def test_unsupported_kdf_has_no_fallback(self):
        with patch.object(app, 'Argon2id', side_effect=app.UnsupportedAlgorithm('unavailable')) as kdf:
            with self.assertRaises(app.UnsupportedAlgorithm): app.LockedEndpoint(self.endpoint.path, PASSWORD)
            self.assertEqual(kdf.call_count, 1)

    def test_backup_does_not_touch_acceptance_database(self):
        db = self.endpoint.path / 'received.sqlite'
        with sqlite3.connect(db) as connection:
            connection.execute('CREATE TABLE marker (value TEXT)')
            connection.execute("INSERT INTO marker VALUES('retained')")
        before = db.read_bytes()
        self.endpoint.backup_key(self.root / 'backup.icp-key-backup', PASSWORD, self.pin)
        self.assertEqual(db.read_bytes(), before)

    def test_checked_key_recovery_retains_original_replay_state(self):
        policy, raw = self.prepared_transfer()
        _, receipt = self.endpoint.receive(policy, raw, 106)
        backup = self.root / 'recovery.icp-key-backup'
        self.endpoint.backup_key(backup, PASSWORD, self.pin)
        saved_db = next(self.endpoint.path.glob('received-*.sqlite'))
        before = saved_db.read_bytes()
        self.keyfile.unlink()
        with self.assertRaises(OSError): app.LockedEndpoint(self.endpoint.path, PASSWORD)
        checked = app.base.read_bytes(backup, app.MAX_STORE, private=True)
        app.unlock(checked, PASSWORD, self.pin)
        app.base.write_new(self.keyfile, checked)  # Restore this file only; DB stays in place.
        reopened = app.LockedEndpoint(self.endpoint.path, PASSWORD)
        self.assertEqual(reopened.receipt(policy, receipt['body']['transfer_id']), receipt)
        with self.assertRaises(ValueError): reopened.receive(policy, raw, 107)
        self.assertEqual(saved_db.read_bytes(), before)

    def test_missing_database_never_silently_resets_replay_state(self):
        policy, raw = self.prepared_transfer()
        self.endpoint.receive(policy, raw, 106)
        db = next(self.endpoint.path.glob('received-*.sqlite'))
        db.unlink()
        with self.assertRaises(OSError): app.LockedEndpoint(self.endpoint.path, PASSWORD).receive(policy, raw, 107)
        self.assertFalse(db.exists())

    def test_database_without_guard_is_not_adopted(self):
        policy, raw = self.prepared_transfer()
        self.endpoint.receive(policy, raw, 106)
        db = next(self.endpoint.path.glob('received-*.sqlite'))
        before = db.read_bytes()
        guard = next(self.endpoint.path.glob('received-*.icp-state-guard')); guard.unlink()
        with self.assertRaises(ValueError): self.endpoint.receive(policy, raw, 107)
        self.assertFalse(guard.exists())
        self.assertEqual(db.read_bytes(), before)

    def test_empty_or_incomplete_database_is_not_reinitialized(self):
        policy, raw = self.prepared_transfer()
        self.endpoint.receive(policy, raw, 106)
        db = next(self.endpoint.path.glob('received-*.sqlite'))
        db.write_bytes(b'')
        with self.assertRaises(ValueError): self.endpoint.receive(policy, raw, 107)
        self.assertEqual(db.read_bytes(), b'')
        with sqlite3.connect(db) as connection: connection.execute('CREATE TABLE unrelated(x)')
        before = db.read_bytes()
        with self.assertRaises(sqlite3.Error): self.endpoint.receive(policy, raw, 107)
        self.assertEqual(db.read_bytes(), before)

    def test_guard_permissions_symlink_and_policy_substitution_reject(self):
        policy, raw = self.prepared_transfer()
        self.endpoint.receive(policy, raw, 106)
        guard = next(self.endpoint.path.glob('received-*.icp-state-guard'))
        saved = guard.read_bytes()
        guard.chmod(0o644)
        with self.assertRaises(ValueError): self.endpoint.receive(policy, raw, 107)
        guard.chmod(0o600)
        body = json.loads(saved); body['policy_id'] = '00' * 48
        guard.write_bytes(app.lab.canonical(body))
        with self.assertRaises(ValueError): self.endpoint.receive(policy, raw, 107)
        guard.unlink()
        target = self.root / 'outside-guard'; target.write_bytes(saved); target.chmod(0o600)
        guard.symlink_to(target)
        with self.assertRaises(OSError): self.endpoint.receive(policy, raw, 107)

    def test_concurrent_first_acceptance_has_one_claim(self):
        policy, raw = self.prepared_transfer()
        policy_file, envelope_file = self.root / 'parallel-policy.json', self.root / 'parallel-envelope.json'
        app.base.write_json(policy_file, policy.body())
        app.base.write_new(envelope_file, raw)
        probe = '''import concurrent.futures, faulthandler, json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
import pq_locked_adapter as app
faulthandler.dump_traceback_later(5)
password = sys.stdin.buffer.read(1025)  # Fictional test-only IPC, never an argument.
policy = app.base.load_policy(sys.argv[3], sys.argv[4])
raw = app.base.read_bytes(sys.argv[5], app.lab.MAX_WIRE)
def receive(_):
    try:
        app.LockedEndpoint(sys.argv[2], password).receive(policy, raw, 106)
        return True
    except (ValueError, OSError, sqlite3.Error):
        return False
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    count = list(pool.map(receive, range(2))).count(True)
faulthandler.cancel_dump_traceback_later()
print(json.dumps({'claims': count}))
'''
        try:
            result = subprocess.run([sys.executable, '-c', probe, str(ROOT / 'scripts'),
                str(self.endpoint.path), str(policy_file), policy.id, str(envelope_file)],
                input=PASSWORD, capture_output=True, timeout=20, check=True)
        except subprocess.TimeoutExpired as exc:
            self.fail('Concurrent unlock timed out; diagnostic stack: ' + (exc.stderr or b'').decode(errors='replace'))
        self.assertEqual(json.loads(result.stdout)['claims'], 1)

    def test_sqlite_crash_journal_recovers_without_losing_committed_receipt(self):
        policy, raw = self.prepared_transfer()
        _, receipt = self.endpoint.receive(policy, raw, 106)
        path = next(self.endpoint.path.glob('received-*.sqlite'))
        writer = '''import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.execute('PRAGMA cache_size=1')
db.execute('BEGIN IMMEDIATE')
for i in range(500):
    db.execute('INSERT INTO recipient_receipts VALUES(?,?)', ('uncommitted-'+str(i), 'fictional'*512))
os._exit(0)
'''
        subprocess.run([sys.executable, '-c', writer, str(path)], check=True, timeout=15)
        self.assertTrue(Path(str(path) + '-journal').exists())
        reopened = app.LockedEndpoint(self.endpoint.path, PASSWORD)
        self.assertEqual(reopened.receipt(policy, receipt['body']['transfer_id']), receipt)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM recipient_receipts').fetchone()[0], 1)
        with self.assertRaises(ValueError): reopened.receive(policy, raw, 107)

    def test_public_record_export_recovers_without_rekey_or_state_reset(self):
        output = self.root / 'recovered-public.json'
        args = app.parser().parse_args(['public', '--endpoint', str(self.endpoint.path), '--output', str(output)])
        with patch.object(app, 'read_password', return_value=PASSWORD): result = app.run(args)
        self.assertEqual(result['endpoint_id'], self.pin)
        self.assertEqual(app.base.read_json(output), self.endpoint.public())
        self.assertEqual(self.keyfile.read_bytes(), self.raw)

    def test_cli_wrong_unlock_suppresses_secret_values(self):
        reader, writer = os.pipe()
        wrong = b'wrong fictional CLI password 12345'
        try:
            os.write(writer, wrong); os.close(writer); writer = None
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/pq_locked_adapter.py'),
                '--passphrase-fd', str(reader), 'backup-key', '--endpoint', str(self.endpoint.path),
                '--endpoint-id', self.pin, '--output', str(self.root / 'failed.icp-key-backup')],
                capture_output=True, pass_fds=(reader,), timeout=15)
        finally:
            os.close(reader)
            if writer is not None: os.close(writer)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        for secret in (wrong, PASSWORD, self.endpoint.identity.private_bytes_raw().hex().encode(), self.raw):
            self.assertNotIn(secret, result.stderr)


class PassphraseInputTests(unittest.TestCase):
    def pipe(self, raw):
        reader, writer = os.pipe()
        os.write(writer, raw); os.close(writer)
        self.addCleanup(os.close, reader)
        return reader

    def test_fd_reads_exact_raw_bytes_to_eof(self):
        self.assertEqual(app.read_password(self.pipe(PASSWORD)), PASSWORD)

    def test_fd_rejects_empty_oversize_and_line_terminated_secrets(self):
        for raw in (b'', b'x' * 1025, PASSWORD + b'\n'):
            with self.assertRaises(ValueError): app.read_password(self.pipe(raw))

    def test_fd_rejects_world_readable_files_and_special_devices(self):
        for descriptor in (-1, True, 2 ** 70):
            with self.assertRaises(ValueError): app.read_password(descriptor)
        with tempfile.TemporaryFile() as stream:
            stream.write(PASSWORD); stream.seek(0); os.fchmod(stream.fileno(), 0o644)
            with self.assertRaises(ValueError): app.read_password(stream.fileno())
        with open('/dev/null', 'rb') as stream:
            with self.assertRaises(ValueError): app.read_password(stream.fileno())

    def test_fd_rejects_nonclosing_pipe_with_bounded_wait(self):
        descriptor = self.pipe(PASSWORD)
        with patch.object(app.select, 'select', return_value=([], [], [])):
            with self.assertRaises(ValueError): app.read_password(descriptor)

    def test_noninteractive_default_does_not_fallback_to_echo(self):
        with patch.object(app.sys.stdin, 'isatty', return_value=False), patch.object(app.getpass, 'getpass') as prompt:
            with self.assertRaises(ValueError): app.read_password()
            prompt.assert_not_called()

    def test_tty_creation_confirmation_must_match(self):
        with patch.object(app.sys.stdin, 'isatty', return_value=True), patch.object(app.getpass, 'getpass',
                side_effect=['fictional passphrase one', 'fictional passphrase two']):
            with self.assertRaises(ValueError): app.read_password(confirm=True)

    def test_tty_no_echo_warning_is_fatal(self):
        def warn(*args):
            import warnings
            warnings.warn('no echo unavailable', app.getpass.GetPassWarning)
        with patch.object(app.sys.stdin, 'isatty', return_value=True), patch.object(app.getpass, 'getpass', side_effect=warn):
            with self.assertRaises(app.getpass.GetPassWarning): app.read_password()

    def test_cli_never_accepts_passphrase_argument_or_silent_stdin(self):
        for arguments in (['--passphrase', PASSWORD.decode()],
                          ['keygen', '--endpoint', '/unused', '--role', 'sender', '--output', '/unused-public']):
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/pq_locked_adapter.py'), *arguments],
                                    input=PASSWORD, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PASSWORD, result.stdout + result.stderr)

    def test_public_policy_command_never_prompts_for_password(self):
        args = app.parser().parse_args(['policy', '--approver', 'a', '--sender', 's', '--recipient', 'r', '--output', 'p'])
        with patch.object(app, 'read_password') as read, patch.object(app.base, 'run', return_value={'public': True}):
            self.assertEqual(app.run(args), {'public': True})
            read.assert_not_called()

    def test_locked_separate_process_demo(self):
        spec = importlib.util.spec_from_file_location('locked_demo', ROOT / 'examples/pq_locked_file_exchange.py')
        # Example imports its sibling relay helper as a normal CLI script does.
        sys.path.insert(0, str(ROOT / 'examples'))
        try:
            demo = importlib.util.module_from_spec(spec); spec.loader.exec_module(demo)
            result = demo.demo()
        finally:
            sys.path.remove(str(ROOT / 'examples'))
        for field in ('recipient_bytes_match', 'receipt_signature_verified', 'receipt_recovered_after_unlock',
                      'replay_rejected_after_unlock', 'wrong_password_rejected', 'encrypted_key_backup_verified'):
            self.assertTrue(result[field])
        for field in ('plaintext_key_files_created', 'passwords_in_arguments', 'endpoint_state_restored', 'hardware_isolation_tested'):
            self.assertFalse(result[field])


if __name__ == '__main__':
    unittest.main()
