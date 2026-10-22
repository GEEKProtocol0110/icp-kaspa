#!/usr/bin/env python3
"""One-object loopback HTTP relay for fictional recipient-adapter tests only.

Opaque bytes in memory. No endpoint/key path, filesystem export or remote bind.
This is a transport example, not an authenticated production relay service.
"""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from pq_recipient_lab import MAX_WIRE


class Relay(HTTPServer):
    def __init__(self):
        self.object_id = None
        self.payload = None
        super().__init__(('127.0.0.1', 0), Handler)


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *args):
        pass

    def reply(self, status, raw=b''):
        self.send_response(status)
        self.send_header('Content-Type', 'application/octet-stream')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def identifier(self):
        match = re.fullmatch(r'/envelope/([0-9a-f]{64})', self.path)
        return match.group(1) if match else None

    def do_PUT(self):
        identifier = self.identifier()
        lengths = self.headers.get_all('Content-Length', [])
        if (identifier is None or self.headers.get('Transfer-Encoding') is not None
                or len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,7}', lengths[0])):
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
        if len(raw) != length or hashlib.sha256(raw).hexdigest() != identifier:
            self.reply(400)
        elif self.server.payload is None:
            self.server.object_id, self.server.payload = identifier, raw
            self.reply(201)
        elif self.server.object_id == identifier and self.server.payload == raw:
            self.reply(204)
        else:
            self.reply(409)

    def do_GET(self):
        if self.identifier() is not None and self.identifier() == self.server.object_id:
            self.reply(200, self.server.payload)
        else:
            self.reply(404)


if __name__ == '__main__':
    with Relay() as server:
        print(json.dumps(dict(host='127.0.0.1', port=server.server_port,
                              mode='LOOPBACK_PQ_CIPHERTEXT_RELAY_EXPERIMENT')), flush=True)
        server.serve_forever()
