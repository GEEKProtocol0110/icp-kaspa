#!/usr/bin/env python3
"""Experimental one-object mTLS transport. PQ envelope security stays separate.

TLS uses conventional certificate authentication. This loopback lab is not a public
service, PKI enrollment system, durable mailbox or production HTTP server.
"""
import hashlib
import hmac
import json
from http.client import HTTPException, HTTPSConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import ssl
import sys

import pq_locked_adapter as locked

MAX_WIRE = locked.lab.MAX_WIRE
TIMEOUT = 3


def pin(der):
    """Pin the exact DER certificate, not a mutable display name."""
    return hashlib.sha384(der).hexdigest()


def checked_pin(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{96}', value):
        raise ValueError('Expected an authenticated SHA-384 certificate pin')
    return value


def context(*, server, ca, certificate, key, password):
    """Explicit trust and encrypted PEM only; no default roots or key-log env."""
    password = locked.password_bytes(password)
    raw = locked.base.read_bytes(key, 32768, private=True)
    if not raw.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n'):
        raise ValueError('Encrypted PKCS8 TLS key required')
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca))
    ctx.load_cert_chain(str(certificate), str(key), password=lambda: password)
    ctx.set_alpn_protocols(['http/1.1'])
    ctx.options |= ssl.OP_NO_TICKET
    if server:
        ctx.num_tickets = 0
    return ctx


def object_id(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_WIRE:
        raise ValueError('Envelope outside transport bound')
    return hashlib.sha384(raw).hexdigest()


class Client:
    """An explicitly configured peer. No redirects, proxies or HTTP fallback."""
    def __init__(self, *, host, port, server_pin, ca, certificate, key, password):
        if (not isinstance(host, str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host)
                or isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535):
            raise ValueError('Invalid fixed transport address')
        self.host, self.port = host, port
        self.server_pin = checked_pin(server_pin)
        self.context = context(server=False, ca=ca, certificate=certificate, key=key, password=password)

    def request(self, method, identifier, raw=None):
        checked_pin(identifier)
        if method not in ('PUT', 'GET') or (method == 'PUT' and object_id(raw) != identifier):
            raise ValueError('Invalid transport operation')
        if method == 'GET' and raw is not None:
            raise ValueError('GET has no body')
        connection = HTTPSConnection(self.host, self.port, timeout=TIMEOUT, context=self.context)
        try:
            # Authenticate the certificate BEFORE emitting any HTTP request/body.
            connection.connect()
            if not hmac.compare_digest(pin(connection.sock.getpeercert(binary_form=True)), self.server_pin):
                raise ValueError('Relay certificate pin mismatch')
            if (connection.sock.version() != 'TLSv1.3'
                    or connection.sock.selected_alpn_protocol() != 'http/1.1'):
                raise ValueError('Unexpected transport protocol')
            connection.request(method, '/envelope/' + identifier, body=raw,
                               headers={'Connection': 'close'})
            response = connection.getresponse()
            lengths = response.headers.get_all('Content-Length', [])
            if (response.headers.get_all('Transfer-Encoding', []) or len(lengths) != 1
                    or not re.fullmatch(r'[0-9]{1,6}', lengths[0])):
                raise ValueError('Invalid response framing')
            length = int(lengths[0])
            if length > MAX_WIRE or (method == 'PUT' and length != 0):
                raise ValueError('Response outside transport bound')
            expected = (201, 204) if method == 'PUT' else (200,)
            if response.status not in expected:
                raise ValueError('Relay rejected operation')
            received = response.read(length + 1)
            if len(received) != length or (method == 'GET' and object_id(received) != identifier):
                raise ValueError('Transport bytes differ')
            return received
        finally:
            connection.close()

    def put(self, raw):
        identifier = object_id(raw)
        self.request('PUT', identifier, raw)
        return identifier

    def get(self, identifier):
        return self.request('GET', identifier)


class Relay(HTTPServer):
    """One immutable opaque object in RAM, separate upload/download certificates."""
    def __init__(self, *, context, upload_pin, download_pin):
        self.upload_pin, self.download_pin = checked_pin(upload_pin), checked_pin(download_pin)
        if self.upload_pin == self.download_pin:
            raise ValueError('Separate TLS role certificates required')
        if (context.verify_mode != ssl.CERT_REQUIRED
                or context.minimum_version != ssl.TLSVersion.TLSv1_3
                or context.maximum_version != ssl.TLSVersion.TLSv1_3):
            raise ValueError('Mutually authenticated TLS 1.3 required')
        self.tls_context = context
        self.object_id = self.payload = None
        super().__init__(('127.0.0.1', 0), Handler)

    def get_request(self):
        sock, address = super().get_request()
        sock.settimeout(TIMEOUT)
        try:
            stream = self.tls_context.wrap_socket(sock, server_side=True)
            if stream.selected_alpn_protocol() != 'http/1.1':
                stream.close()
                raise OSError('HTTP/1.1 ALPN required')
            return stream, address
        except BaseException:
            sock.close()
            raise

    def handle_error(self, request, client_address):
        # No exception dumps, request bytes, credentials or peer metadata in logs.
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, raw=b''):
        self.close_connection = True
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(raw)

    def allowed(self, expected):
        if not hmac.compare_digest(pin(self.connection.getpeercert(binary_form=True)), expected):
            self.reply(403)
            return False
        return True

    def identifier(self):
        match = re.fullmatch('/envelope/([0-9a-f]{96})', self.path)
        return match.group(1) if match else None

    def do_PUT(self):
        if not self.allowed(self.server.upload_pin):
            return
        identifier = self.identifier()
        lengths = self.headers.get_all('Content-Length', [])
        if (identifier is None or self.headers.get_all('Transfer-Encoding', [])
                or len(lengths) != 1 or not re.fullmatch('[0-9]{1,6}', lengths[0])):
            self.reply(400)
            return
        length = int(lengths[0])
        if not 0 < length <= MAX_WIRE:
            self.reply(413)
            return
        try:
            raw = self.rfile.read(length)
        except TimeoutError:
            self.reply(408)
            return
        if len(raw) != length or object_id(raw) != identifier:
            self.reply(400)
        elif self.server.payload is None:
            self.server.object_id, self.server.payload = identifier, raw
            self.reply(201)
        elif self.server.object_id == identifier and self.server.payload == raw:
            self.reply(204)
        else:
            self.reply(409)

    def do_GET(self):
        if not self.allowed(self.server.download_pin):
            return
        lengths = self.headers.get_all('Content-Length', [])
        if (self.headers.get_all('Transfer-Encoding', []) or lengths not in ([], ['0'])):
            self.reply(400)
        elif self.identifier() is not None and self.identifier() == self.server.object_id:
            self.reply(200, self.server.payload)
        else:
            self.reply(404)


def main():
    parser = locked.LockedParser(description=__doc__)
    parser.add_argument('--passphrase-fd', type=int)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--certificate', required=True)
    parser.add_argument('--key', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    serve = commands.add_parser('serve')
    serve.add_argument('--upload-pin', required=True)
    serve.add_argument('--download-pin', required=True)
    for command in ('put', 'get'):
        operation = commands.add_parser(command)
        operation.add_argument('--host', required=True)
        operation.add_argument('--port', required=True, type=int)
        operation.add_argument('--server-pin', required=True)
        if command == 'put':
            operation.add_argument('--input', required=True)
        else:
            operation.add_argument('--object-id', required=True)
            operation.add_argument('--output', required=True)
    args = parser.parse_args()
    try:
        password = locked.read_password(args.passphrase_fd)
        credentials = dict(ca=args.ca, certificate=args.certificate, key=args.key, password=password)
        if args.command == 'serve':
            with Relay(context=context(server=True, **credentials), upload_pin=args.upload_pin,
                       download_pin=args.download_pin) as server:
                print(json.dumps(dict(host='127.0.0.1', port=server.server_port,
                                      mode='LOOPBACK_MTLS13_PQ_ENVELOPE_EXPERIMENT')), flush=True)
                server.serve_forever()
        else:
            client = Client(host=args.host, port=args.port, server_pin=args.server_pin, **credentials)
            if args.command == 'put':
                result = dict(object_id=client.put(locked.base.read_bytes(args.input, MAX_WIRE)))
            else:
                raw = client.get(args.object_id)
                locked.base.write_new(args.output, raw)
                result = dict(object_id=args.object_id, bytes=len(raw))
            print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, TypeError, KeyError, OSError, EOFError, HTTPException):
        print('Authenticated transport failed; input details suppressed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
