import datetime
from binascii import hexlify
from xmlsec.crypto import _cert_fingerprint as xmlsec_cert_fingerprint
from cryptography.hazmat.primitives.serialization import Encoding as CryptoSerializationEncoding
from cryptography.hazmat.primitives.hashes import SHA256

def is_cert_expired(cert):
    if hasattr(cert, 'not_valid_after_utc'):
        return cert.not_valid_after_utc < datetime.datetime.now(datetime.UTC)
    else:
        return cert.not_valid_after < datetime.datetime.now()

def update_fp_pem_mapping(certificates, cert, filter_expired=True):
    fp, cert = xmlsec_cert_fingerprint(cert)
    if filter_expired and is_cert_expired(cert):
        return
    fp = hexlify(cert.fingerprint(SHA256())).lower().decode('ascii')
    cert = cert.public_bytes(CryptoSerializationEncoding.PEM).decode('ascii')
    certificates.update({fp: cert})

# def b64_slugify(s):
#     return s.replace('/', '_').replace('+', '-')
