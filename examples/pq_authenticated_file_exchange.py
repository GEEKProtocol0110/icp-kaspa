#!/usr/bin/env python3
"""Fictional PQ exchange: encrypted endpoints plus separately pinned mTLS peers.

All processes still share ONE trusted host. No native transaction or real data.
"""
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile

from pq_locked_file_exchange import demo as locked_demo
from pq_tls_test_pki import TestPKI, transport

ROOT = Path(__file__).resolve().parents[1]


def handoff(raw):
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        pki = TestPKI(folder)
        server, sender, recipient = (pki.issue('relay', server=True), pki.issue('upload'), pki.issue('download'))

        def launch(record, *args, background=False):
            reader, writer = os.pipe()
            try:
                os.write(writer, record['password'])
            finally:
                os.close(writer)
            command = [sys.executable, str(ROOT / 'scripts/pq_authenticated_transport.py'),
                       '--passphrase-fd', str(reader), '--ca', str(record['ca']),
                       '--certificate', str(record['certificate']), '--key', str(record['key']), *map(str, args)]
            try:
                if background:
                    return subprocess.Popen(command, pass_fds=(reader,), stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
                result = subprocess.run(command, pass_fds=(reader,), capture_output=True, timeout=15)
            finally:
                os.close(reader)
            if result.returncode:
                raise AssertionError('Fictional authenticated transport failed; output suppressed')
            return json.loads(result.stdout)

        relay = launch(server, 'serve', '--upload-pin', sender['pin'], '--download-pin', recipient['pin'], background=True)
        try:
            if not select.select([relay.stdout], [], [], 10)[0]:
                raise AssertionError('Authenticated relay did not start')
            ready = json.loads(relay.stdout.readline())
            common = ['--host', ready['host'], '--port', ready['port'], '--server-pin', server['pin']]
            transport.locked.base.write_new(folder / 'envelope.json', raw)
            result = launch(sender, 'put', *common, '--input', folder / 'envelope.json')
            launch(recipient, 'get', *common, '--object-id', result['object_id'], '--output', folder / 'received.json')
            received = (folder / 'received.json').read_bytes()
            if received != raw:
                raise AssertionError('Authenticated relay bytes differ')
            return received
        finally:
            relay.terminate()
            try:
                relay.wait(timeout=5)
            except subprocess.TimeoutExpired:
                relay.kill()
                relay.wait(timeout=5)
            relay.stdout.close()


def demo():
    result = locked_demo(handoff=handoff)
    result.update(scenario='FICTIONAL_PQ_ENVELOPE_MUTUAL_TLS13_ONE_HOST',
                  transport='TLS_1_3_MUTUAL_CONVENTIONAL_CERTIFICATES',
                  transport_client_processes=2, server_certificate_pin_checked_before_http=True,
                  separate_upload_download_certificates=True, encrypted_tls_private_keys=True,
                  post_quantum_tls_tested=False, independent_host_isolation_tested=False)
    return result


if __name__ == '__main__':
    print(json.dumps(demo(), indent=2, sort_keys=True))
