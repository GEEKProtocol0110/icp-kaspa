"""Ephemeral fictional ECDSA certificates ONLY for loopback demos/tests.

Not identity enrollment, a production CA, post-quantum TLS, or persisted CA
recovery. Every private PEM is encrypted before publication to an owner-only
temporary directory. CA private material never leaves this test process.
"""
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import pq_authenticated_transport as transport


class TestPKI:
    def __init__(self, folder):
        self.folder = Path(folder)
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Fictional ICP loopback test CA')])
        self.ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                        .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=2))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                        .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), False)
                        .sign(self.key, hashes.SHA256()))
        self.ca = self.folder / 'ca.pem'
        transport.locked.base.write_new(self.ca, self.ca_cert.public_bytes(serialization.Encoding.PEM))

    def issue(self, name, *, server=False, expired=False):
        private = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        builder = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                   .issuer_name(self.ca_cert.subject).public_key(private.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(hours=1))
                   .not_valid_after(now - timedelta(minutes=1) if expired else now + timedelta(hours=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(private.public_key()), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), False)
                   .add_extension(x509.ExtendedKeyUsage([
                       ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), True))
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
        cert = builder.sign(self.key, hashes.SHA256())
        password = os.urandom(32).hex().encode()
        paths = dict(ca=self.ca, certificate=self.folder / (name + '.pem'), key=self.folder / (name + '.key'))
        transport.locked.base.write_new(paths['certificate'], cert.public_bytes(serialization.Encoding.PEM))
        transport.locked.base.write_new(paths['key'], private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password)))
        return dict(**paths, password=password, pin=transport.pin(cert.public_bytes(serialization.Encoding.DER)))


def credentials(record):
    return {key: record[key] for key in ('ca', 'certificate', 'key', 'password')}
