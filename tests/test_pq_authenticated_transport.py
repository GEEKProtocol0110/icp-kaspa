"""Real loopback TLS handshakes and adversarial transport boundaries."""
import hashlib
from http.client import HTTPSConnection
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'examples'))
from pq_tls_test_pki import TestPKI, credentials, transport as t


class AuthenticatedTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.folder = Path(cls.temporary.name)
        cls.pki = TestPKI(cls.folder)
        cls.relay_keys = cls.pki.issue('relay', server=True)
        cls.upload = cls.pki.issue('upload')
        cls.download = cls.pki.issue('download')
        cls.stranger = cls.pki.issue('stranger')
        cls.expired = cls.pki.issue('expired', expired=True)
        cls.expired_server = cls.pki.issue('expired-server', server=True, expired=True)
        (cls.folder / 'other').mkdir(mode=0o700)
        cls.other = TestPKI(cls.folder / 'other')
        cls.foreign = cls.other.issue('foreign')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.start()

    def start(self, keys=None):
        self.server = t.Relay(context=t.context(server=True, **credentials(keys or self.relay_keys)),
                              upload_pin=self.upload['pin'], download_pin=self.download['pin'])
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs=dict(poll_interval=0.01), daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    def tearDown(self):
        self.stop()

    def client(self, record=None, **changes):
        args = dict(host='127.0.0.1', port=self.server.server_port, server_pin=self.relay_keys['pin'],
                    **credentials(record or self.upload))
        args.update(changes)
        return t.Client(**args)

    def request(self, method, path, *, record=None, headers=(), body=None):
        connection = HTTPSConnection('127.0.0.1', self.server.server_port, timeout=5,
                                     context=t.context(server=False, **credentials(record or self.upload)))
        try:
            connection.putrequest(method, path)
            for name, value in headers:
                connection.putheader(name, value)
            connection.endheaders(body)
            response = connection.getresponse()
            result = response.status, response.read(t.MAX_WIRE + 1)
            return result
        finally:
            connection.close()

    def bad_response(self, status=200, body=b'x', headers=None):
        class BadHandler(t.Handler):
            def do_GET(self):
                self.close_connection = True
                self.send_response(status)
                for key, value in headers if headers is not None else [('Content-Length', str(len(body)))]:
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(body)
        self.server.RequestHandlerClass = BadHandler

    def test_authenticated_byte_exchange(self):
        raw = b'FICTIONAL opaque binary\x00\xff'
        identifier = self.client().put(raw)
        self.assertEqual(hashlib.sha384(raw).hexdigest(), identifier)
        self.assertEqual(self.client(self.download).get(identifier), raw)

    def test_upload_is_immutable_and_retry_is_idempotent(self):
        first = self.client().put(b'first')
        self.assertEqual(self.client().put(b'first'), first)
        with self.assertRaises(ValueError):
            self.client().put(b'second')
        self.assertEqual(self.server.payload, b'first')

    def test_role_certificates_do_not_swap_permissions(self):
        with self.assertRaises(ValueError):
            self.client(self.download).put(b'blocked')
        self.assertIsNone(self.server.payload)
        identifier = self.client().put(b'only recipient may download')
        with self.assertRaises(ValueError):
            self.client().get(identifier)
        self.assertEqual(self.client(self.download).get(identifier), self.server.payload)

    def test_ca_valid_but_unpinned_client_is_denied(self):
        with self.assertRaises(ValueError):
            self.client(self.stranger).put(b'blocked')
        self.assertIsNone(self.server.payload)

    def test_wrong_server_pin_precedes_http_request(self):
        seen = []
        class Observe(t.Handler):
            def do_PUT(self):
                seen.append(True)
                super().do_PUT()
        self.server.RequestHandlerClass = Observe
        with self.assertRaises(ValueError):
            self.client(server_pin='0' * 96).put(b'must not be sent')
        self.assertEqual(seen, [])
        self.assertIsNone(self.server.payload)

    def test_wrong_server_ca_is_denied(self):
        with self.assertRaises(ssl.SSLError):
            self.client(ca=self.other.ca).put(b'blocked')
        self.assertIsNone(self.server.payload)

    def test_untrusted_client_ca_is_denied(self):
        with self.assertRaises((ssl.SSLError, OSError)):
            self.client(self.foreign, ca=self.pki.ca).put(b'blocked')
        self.assertIsNone(self.server.payload)

    def test_hostname_mismatch_is_denied(self):
        context = self.client().context
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=5) as raw:
            with self.assertRaises(ssl.SSLError):
                context.wrap_socket(raw, server_hostname='wrong.example')

    def test_client_certificate_is_mandatory(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=str(self.pki.ca))
        context.set_alpn_protocols(['http/1.1'])
        connection = HTTPSConnection('127.0.0.1', self.server.server_port, timeout=5, context=context)
        try:
            with self.assertRaises((ssl.SSLError, OSError)):
                connection.request('GET', '/envelope/' + '0' * 96)
                connection.getresponse()
        finally:
            connection.close()
        self.assertIsNone(self.server.payload)

    def test_expired_client_is_denied(self):
        with self.assertRaises((ssl.SSLError, OSError)):
            self.client(self.expired).put(b'blocked')
        self.assertIsNone(self.server.payload)

    def test_expired_server_is_denied_even_with_correct_pin(self):
        self.stop()
        self.start(self.expired_server)
        with self.assertRaises(ssl.SSLError):
            self.client(server_pin=self.expired_server['pin']).put(b'blocked')

    def test_server_rejects_client_certificate_purpose(self):
        with self.assertRaises((ssl.SSLError, OSError)):
            self.client(self.relay_keys).put(b'blocked')

    def test_tls12_is_rejected(self):
        context = self.client().context
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=5) as raw:
            with self.assertRaises(ssl.SSLError):
                context.wrap_socket(raw, server_hostname='127.0.0.1')
        self.assertIsNone(self.server.payload)

    def test_missing_alpn_does_not_accept_http(self):
        context = self.client().context
        context.set_alpn_protocols([])
        connection = HTTPSConnection('127.0.0.1', self.server.server_port, timeout=5, context=context)
        try:
            with self.assertRaises(OSError):
                connection.request('PUT', '/envelope/' + t.object_id(b'x'), b'x')
                connection.getresponse()
        finally:
            connection.close()
        self.assertIsNone(self.server.payload)

    def test_cleartext_http_is_not_accepted(self):
        with socket.create_connection(('127.0.0.1', self.server.server_port), timeout=5) as raw:
            raw.sendall(b'GET / HTTP/1.0\r\n\r\n')
            try:
                response = raw.recv(1024)
            except ConnectionResetError:
                response = b''
        self.assertNotIn(b'HTTP/', response)
        self.assertIsNone(self.server.payload)

    def test_maximum_wire_size_roundtrip(self):
        raw = b'x' * t.MAX_WIRE
        self.assertEqual(self.client(self.download).get(self.client().put(raw)), raw)

    def test_empty_and_oversize_uploads_reject_before_connect(self):
        client = self.client()
        with patch.object(t.HTTPSConnection, 'connect', side_effect=AssertionError('Unexpected connection')):
            for raw in (b'', b'x' * (t.MAX_WIRE + 1)):
                with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                    client.put(raw)

    def test_corrupt_upload_does_not_occupy_slot(self):
        self.assertEqual(self.request('PUT', '/envelope/' + '0' * 96,
                                     headers=[('Content-Length', '1')], body=b'x')[0], 400)
        self.assertIsNone(self.server.payload)

    def test_duplicate_lengths_and_chunked_requests_reject(self):
        for headers in ([('Content-Length', '1'), ('Content-Length', '1')],
                        [('Content-Length', '1'), ('Transfer-Encoding', 'chunked')], [],
                        [('Content-Length', '-1')], [('Content-Length', '0000001')]):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('PUT', '/envelope/' + t.object_id(b'x'),
                                             headers=headers, body=b'x')[0], 400)
        self.assertIsNone(self.server.payload)

    def test_server_rejects_oversize_length_before_body(self):
        self.assertEqual(self.request('PUT', '/envelope/' + '0' * 96,
                                     headers=[('Content-Length', str(t.MAX_WIRE + 1))])[0], 413)
        self.assertIsNone(self.server.payload)

    def test_unknown_and_filesystem_paths_do_not_serve(self):
        for path in ('/etc/passwd', '/envelope/' + '0' * 96, '/envelope/' + '0' * 96 + '?x=1'):
            with self.subTest(path=path):
                self.assertEqual(self.request('GET', path, record=self.download)[0], 404)

    def test_get_with_body_framing_rejects(self):
        identifier = self.client().put(b'present')
        for headers in ([('Content-Length', '1')], [('Content-Length', '0'), ('Content-Length', '0')],
                        [('Transfer-Encoding', 'chunked')]):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('GET', '/envelope/' + identifier, record=self.download,
                                             headers=headers)[0], 400)

    def test_response_redirect_does_not_follow(self):
        self.bad_response(status=302, body=b'', headers=[('Content-Length', '0'), ('Location', 'http://example.invalid')])
        with self.assertRaises(ValueError):
            self.client(self.download).get('0' * 96)

    def test_response_oversize_length_rejects_before_body(self):
        self.bad_response(body=b'', headers=[('Content-Length', str(t.MAX_WIRE + 1))])
        with self.assertRaises(ValueError):
            self.client(self.download).get('0' * 96)

    def test_response_conflicting_or_chunked_framing_rejects(self):
        for headers in ([('Content-Length', '1'), ('Content-Length', '1')],
                        [('Content-Length', '1'), ('Transfer-Encoding', 'chunked')], []):
            with self.subTest(headers=headers):
                self.bad_response(headers=headers)
                with self.assertRaises(ValueError):
                    self.client(self.download).get('0' * 96)

    def test_response_truncation_rejects(self):
        self.bad_response(headers=[('Content-Length', '2')])
        with self.assertRaises(ValueError):
            self.client(self.download).get('0' * 96)

    def test_response_checksum_mismatch_rejects(self):
        self.bad_response()
        with self.assertRaises(ValueError):
            self.client(self.download).get(t.object_id(b'y'))

    def test_proxy_and_keylog_environment_are_not_enabled(self):
        keylog = self.folder / 'must-not-exist.keys'
        with patch.dict(os.environ, SSLKEYLOGFILE=str(keylog), HTTPS_PROXY='http://127.0.0.1:1'):
            client = self.client()
            self.assertIsNone(client.context.keylog_filename)
            self.assertEqual(client.put(b'direct connection'), t.object_id(b'direct connection'))
        self.assertFalse(keylog.exists())

    def test_invalid_pins_roles_and_addresses_reject(self):
        for changes in (dict(server_pin='0' * 64), dict(server_pin='A' * 96),
                        dict(host='https://localhost'), dict(host='user@localhost'), dict(port=True)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.client(**changes)
        with self.assertRaises(ValueError):
            t.Relay(context=self.server.tls_context, upload_pin=self.upload['pin'], download_pin=self.upload['pin'])

    def test_plaintext_key_and_unsafe_permissions_reject(self):
        path = self.folder / 'plain.key'
        t.locked.base.write_new(path, b'-----BEGIN PRIVATE KEY-----\nNOT A REAL KEY\n')
        with self.assertRaises(ValueError):
            self.client(key=path)
        os.chmod(path, 0o644)
        with self.assertRaises(ValueError):
            self.client(key=path)
        path.unlink()

    def test_wrong_key_password_rejects(self):
        with self.assertRaises((ValueError, ssl.SSLError)):
            self.client(password=b'an incorrect fictional passphrase')

    def test_relaxed_server_context_rejects(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        with self.assertRaises(ValueError):
            t.Relay(context=context, upload_pin=self.upload['pin'], download_pin=self.download['pin'])


if __name__ == '__main__':
    unittest.main()
