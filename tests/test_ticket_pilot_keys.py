"""Fresh test-only roles and exact private backup restoration, no network."""
from copy import deepcopy
import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import ticket_pilot_keys as p


class KeySetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.session = self.root / 'session'
        self.backup = self.root / 'backup.zip'
        self.native = p.Addresses()
        self.receipt = p.create(self.session, self.backup, self.native)
        self.files = p.read_session(self.session)

    def tearDown(self):
        self.temp.cleanup()

    def rewritten_archive(self, entries):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as z:
            for name, raw in entries:
                z.writestr(name, raw)
        path = self.root / 'modified.zip'
        p.write_private(path, buffer.getvalue())
        return path, hashlib.sha256(buffer.getvalue()).hexdigest()

    def test_roundtrip_proves_six_distinct_keys_and_has_no_spend_or_rpc(self):
        r = self.receipt
        self.assertEqual((r['distinct_keys'], r['restored_keys_verified']), (6, 6))
        self.assertEqual((r['transactions_signed'], r['rpc_calls'], r['broadcasts']), (0, 0, 0))
        self.assertFalse(r['source_observed'])
        restored = self.root / 'restored'
        p.restore(self.backup, restored, r['backup_sha256'], self.native)
        self.assertEqual(self.files, p.read_session(restored))
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(restored.stat().st_mode & 0o777, 0o700)
        for name in self.files:
            self.assertEqual((restored / name).stat().st_mode & 0o777, 0o600)
        for raw in (self.files[n] for n in self.files if n.endswith('.key')):
            self.assertNotIn(raw.decode(), p.canonical(r).decode())

    def test_new_ceremony_has_distinct_keys_nonces_session_and_addresses(self):
        r = p.create(self.root / 'other', self.root / 'other.zip', self.native)
        self.assertNotEqual(r['session_id'], self.receipt['session_id'])
        self.assertTrue(set(r['funding_addresses'].values()).isdisjoint(
            self.receipt['funding_addresses'].values()))
        a, b = (p.decode(x['manifest.json']) for x in (self.files, p.read_session(self.root / 'other')))
        self.assertTrue({v['run_nonce'] for v in a['runs'].values()}.isdisjoint(
            {v['run_nonce'] for v in b['runs'].values()}))

    def test_existing_destination_and_archive_are_not_overwritten(self):
        original = self.backup.read_bytes()
        with self.assertRaises(FileExistsError):
            p.create(self.session, self.backup, self.native)
        with self.assertRaises(FileExistsError):
            p.create(self.root / 'another', self.backup, self.native)
        with self.assertRaises(FileExistsError):
            p.restore(self.backup, self.session, self.receipt['backup_sha256'], self.native)
        self.assertEqual(self.backup.read_bytes(), original)

    def test_corrupt_archive_or_wrong_expected_digest_fails_before_restore(self):
        for digest in ('00' * 32, 'bad'):
            with self.assertRaises(p.KeyError):
                p.restore(self.backup, self.root / 'restore', digest, self.native)
            self.assertFalse((self.root / 'restore').exists())
        with self.backup.open('ab') as f:
            f.write(b'changed')
        with self.assertRaises(p.KeyError):
            p.restore(self.backup, self.root / 'restore', self.receipt['backup_sha256'], self.native)

    def test_missing_extra_path_traversal_and_duplicate_entries_fail(self):
        entries = list(self.files.items())
        for changed in (entries[:-1], entries + [('extra', b'x')],
                        entries + [('../escape.key', b'x')], entries + [entries[0]]):
            with self.subTest(names=[n for n, _ in changed]):
                path, digest = self.rewritten_archive(changed)
                with self.assertRaises(p.KeyError):
                    p.restore(path, self.root / 'restore', digest, self.native)
                self.assertFalse((self.root / 'restore').exists())
                path.unlink()

    def test_swapped_wrong_and_malformed_keys_fail(self):
        for value in (self.files['refund/funding.key'], b'00' * 32, b'no key', b'F' * 64):
            files = dict(self.files, **{'consume/funding.key': value})
            with self.assertRaises(Exception):
                p.verify_material(files, self.native)

    def test_wrong_network_role_nonce_proof_and_address_fail(self):
        original = p.decode(self.files['manifest.json'])
        for mutate in (
            lambda m: m.update(network='mainnet'),
            lambda m: m['runs']['consume'].update(run_nonce=m['runs']['refund']['run_nonce']),
            lambda m: m['runs']['consume']['roles']['funding'].update(proof='00' * 64),
            lambda m: m['runs']['consume']['roles']['funding'].update(address='kaspatest:wrong'),
            lambda m: m['runs']['consume']['roles']['funding'].update(
                proof=m['runs']['refund']['roles']['funding']['proof']),
            lambda m: m['runs']['consume']['roles'].update(extra={}),
        ):
            m = deepcopy(original)
            mutate(m)
            with self.assertRaises(Exception):
                p.verify_material(dict(self.files, **{'manifest.json': p.canonical(m)}), self.native)

    def test_symlinks_hardlinks_and_open_permissions_fail(self):
        key = self.session / 'consume/funding.key'
        saved = key.read_bytes()
        key.chmod(0o644)
        with self.assertRaises(p.KeyError):
            p.read_session(self.session)
        key.chmod(0o600)
        os.link(key, self.root / 'hardlink')
        with self.assertRaises(p.KeyError):
            p.read_session(self.session)
        (self.root / 'hardlink').unlink()
        key.unlink()
        p.write_private(self.root / 'outside', saved)
        key.symlink_to(self.root / 'outside')
        with self.assertRaises(p.KeyError):
            p.read_session(self.session)
        (self.root / 'link').symlink_to(self.session, target_is_directory=True)
        with self.assertRaises(p.KeyError):
            p.read_session(self.root / 'link')

    def test_native_process_receives_public_keys_only_and_no_inherited_credentials(self):
        m = p.decode(self.files['manifest.json'])
        original = subprocess.run
        calls = []
        def run(*args, **kwargs):
            calls.append((args, kwargs))
            return original(*args, **kwargs)
        with patch.object(p.subprocess, 'run', side_effect=run):
            p.verify_material(self.files, self.native)
        self.assertEqual(len(calls), 2)
        for args, kwargs in calls:
            self.assertEqual(args[0][1:], ['addresses'])
            self.assertEqual(kwargs['env'], {'PATH': '/usr/bin:/bin'})
            self.assertEqual(set(p.decode(kwargs['input'])), {r + '_key' for r in p.ROLES})
            for name, raw in self.files.items():
                if name.endswith('.key'):
                    self.assertNotIn(raw, kwargs['input'])
        self.assertEqual(m['network'], 'testnet-10')

    def test_changed_pinned_native_binary_fails_before_process(self):
        self.native.fingerprint = '00' * 32
        with patch.object(p.subprocess, 'run') as run:
            with self.assertRaises(p.KeyError):
                p.verify_material(self.files, self.native)
            run.assert_not_called()

    def test_cli_failure_suppresses_input_and_exception_details(self):
        result = subprocess.run([sys.executable, str(p.ROOT / 'scripts/ticket_pilot_keys.py'),
                                 'restore', str(self.backup), str(self.root / 'restore'),
                                 'PRIVATE_SENTINEL_MUST_NOT_APPEAR'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'')
        self.assertNotIn(b'PRIVATE_SENTINEL', result.stderr)
        self.assertIn(b'Do not fund', result.stderr)

    def test_backup_write_failure_does_not_return_a_ready_receipt(self):
        with patch.object(p.zipfile.ZipFile, 'writestr', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                p.create(self.root / 'failed', self.root / 'failed.zip', self.native)
        self.assertTrue((self.root / 'failed').exists())
        self.assertTrue((self.root / 'failed.zip').exists())


if __name__ == '__main__':
    unittest.main()
