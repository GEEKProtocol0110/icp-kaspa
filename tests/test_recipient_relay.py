"""Loopback-only transport; no endpoint keys or public network service."""
import hashlib
from http.client import HTTPConnection
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'examples'))
from recipient_ciphertext_relay import MAX_WIRE, Relay


class RecipientRelayTests(unittest.TestCase):
    def setUp(self):
        self.server = Relay()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def request(self, method, path, body=None, headers=None):
        connection = HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_loopback_bind_and_exact_opaque_roundtrip(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        raw = b'fictional opaque ciphertext\x00\xff'
        path = '/envelope/' + hashlib.sha256(raw).hexdigest()
        self.assertEqual(self.request('PUT', path, raw), (201, b''))
        self.assertEqual(self.request('GET', path), (200, raw))

    def test_mismatched_hash_and_unknown_object_rejected(self):
        path = '/envelope/' + '00' * 32
        self.assertEqual(self.request('PUT', path, b'fictional'), (400, b''))
        self.assertEqual(self.request('GET', path), (404, b''))
        self.assertIsNone(self.server.payload)

    def test_one_immutable_object_and_idempotent_same_bytes(self):
        first, second = b'one', b'two'
        path = '/envelope/' + hashlib.sha256(first).hexdigest()
        other = '/envelope/' + hashlib.sha256(second).hexdigest()
        self.assertEqual(self.request('PUT', path, first)[0], 201)
        self.assertEqual(self.request('PUT', path, first)[0], 204)
        self.assertEqual(self.request('PUT', other, second)[0], 409)
        self.assertEqual(self.request('GET', path), (200, first))

    def test_size_and_transfer_encoding_limits(self):
        path = '/envelope/' + '00' * 32
        self.assertEqual(self.request('PUT', path, b'', {'Content-Length': str(MAX_WIRE + 1)})[0], 413)
        self.assertEqual(self.request('PUT', path, b'0\r\n\r\n', {'Transfer-Encoding': 'chunked'})[0], 400)
        self.assertIsNone(self.server.payload)

    def test_path_cannot_read_files_or_list_directory(self):
        for path in ('/', '/keys.json', '/../keys.json', '/envelope/' + 'g' * 64):
            self.assertEqual(self.request('GET', path), (404, b''))


if __name__ == '__main__':
    unittest.main()
