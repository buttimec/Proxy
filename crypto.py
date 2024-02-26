import datetime
import ssl
import re

from cryptography import x509
from cryptography.hazmat._oid import NameOID, ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate, DNSName, ExtensionNotFound

_PASSWORD = b"password"

#https://cryptography.io/en/latest/
def load_ca():
    with open('ca.key', 'r') as f:
        data = f.read().encode('utf-8')
        ca_key = load_pem_private_key(data, password = None)

    with open('ca.crt', 'r') as f:
        data = f.read().encode('utf-8')
        ca_cert = x509.load_pem_x509_certificate(data, default_backend())

    return ca_key, ca_cert

def generate_cert(address: tuple[str, int], ca_key: RSAPrivateKey,
                  ca_cert: Certificate) -> tuple[str, str, bytes]:
    encoded_cert = ssl.get_server_certificate(address)
    target_cert = x509.load_pem_x509_certificate(encoded_cert.encode('utf-8'), default_backend())
    target_cn = target_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME).pop().value
    try:
        extensions = target_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(DNSName)
    except ExtensionNotFound:
        extensions = None
    #Generate private key
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    key_filepath = generate_file_name(target_cn, 'key','pem')
    key_filepath = f'cert_cache/{key_filepath}'
    with open(key_filepath, 'wb') as f: #write binary
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(_PASSWORD)
        ))
        f.flush()
        f.close()
    builder = x509.CertificateBuilder().subject_name(
        target_cert.subject
    ).issuer_name(
        ca_cert.issuer
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now()
    ).not_valid_after(
        datetime.datetime.now() + datetime.timedelta(days=30)
    )
    if extensions:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(extension) for extension in extensions
            ]),
            critical=False
        )
    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
    cert_filepath = generate_file_name(target_cn, 'cert','pem')
    cert_filepath = f'cert_cache/{cert_filepath}'
    with open(cert_filepath, 'wb') as f: #write binary
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
        f.flush()
        f.close()
    return cert_filepath, key_filepath, _PASSWORD

def generate_file_name(cn: str, ftype: str, ext: str):
    #wildcatd common names start with *, e.g. *.rte.ie
    fname = cn.replace('*', 'wild')
    fname = re.sub(r'\W', '', fname)
    return f'{fname}_{ftype}.{ext}'

