"""A small certificate authority for the sensor/brain link (mutual TLS).

The brain owns the CA. It issues its own server certificate and, at
enrolment, signs each sensor's certificate request. The sensor's certificate
common name is always the sensor id chosen by the brain, never what the
sensor asked for.
"""
import datetime
import hashlib
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_DAYS = 3650
SERVER_DAYS = 825
SENSOR_DAYS = 825


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode('ascii')


def _cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode('ascii')


def load_key(pem):
    return serialization.load_pem_private_key(pem.encode('ascii') if isinstance(pem, str) else pem, None)


def load_cert(pem):
    return x509.load_pem_x509_certificate(pem.encode('ascii') if isinstance(pem, str) else pem)


def fingerprint(cert_pem_or_der):
    """SHA-256 fingerprint of a certificate, as lowercase hex."""
    if isinstance(cert_pem_or_der, (bytes, bytearray)) and not cert_pem_or_der.startswith(b'-----'):
        der = bytes(cert_pem_or_der)
    else:
        der = load_cert(cert_pem_or_der).public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def common_name(cert):
    if isinstance(cert, (str, bytes)):
        cert = load_cert(cert) if (isinstance(cert, str) or cert.startswith(b'-----')) \
            else x509.load_der_x509_certificate(cert)
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else None


def generate_ca(name='SentinelEdgeAI brain CA'):
    """Return (key_pem, cert_pem) for a new CA."""
    key = _key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'SentinelEdgeAI')])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _key_pem(key), _cert_pem(cert)


def _leaf(ca_key_pem, ca_cert_pem, public_key, cn, days, usage, sans=None):
    ca_key, ca_cert = load_key(ca_key_pem), load_cert(ca_cert_pem)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(minutes=5))
        .not_valid_after(_now() + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return _cert_pem(builder.sign(ca_key, hashes.SHA256()))


def issue_server_cert(ca_key_pem, ca_cert_pem, hostnames=(), ips=()):
    """Return (key_pem, cert_pem) for the brain's sensor-facing TLS endpoint."""
    key = _key()
    sans = [x509.DNSName(h) for h in hostnames] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cn = (list(hostnames) or list(ips) or ['sentinel-brain'])[0]
    cert = _leaf(ca_key_pem, ca_cert_pem, key.public_key(), cn, SERVER_DAYS, ExtendedKeyUsageOID.SERVER_AUTH, sans)
    return _key_pem(key), cert


def make_csr(name='sentinel-sensor'):
    """Sensor side: return (key_pem, csr_pem). The key never leaves the sensor."""
    key = _key()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
           .sign(key, hashes.SHA256()))
    return _key_pem(key), csr.public_bytes(serialization.Encoding.PEM).decode('ascii')


def sign_sensor_csr(ca_key_pem, ca_cert_pem, csr_pem, sensor_id, days=SENSOR_DAYS):
    """Brain side: sign a sensor CSR as a client certificate whose CN is `sensor_id`."""
    csr = x509.load_pem_x509_csr(csr_pem.encode('ascii') if isinstance(csr_pem, str) else csr_pem)
    if not csr.is_signature_valid:
        raise ValueError('certificate request signature is invalid')
    if not isinstance(csr.public_key(), ec.EllipticCurvePublicKey):
        raise ValueError('certificate request must use an EC key')
    return _leaf(ca_key_pem, ca_cert_pem, csr.public_key(), sensor_id, days, ExtendedKeyUsageOID.CLIENT_AUTH)
