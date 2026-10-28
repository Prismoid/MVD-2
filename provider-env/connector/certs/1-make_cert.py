from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

KEY_PATH = "mtls.key"
CRT_PATH = "mtls.crt"
USER_ID = "provider"

with open(KEY_PATH, "rb") as f:
    key = serialization.load_pem_private_key(f.read(), password=None)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, USER_ID)
])

cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("host.docker.internal"),
        ]),
        critical=False
    )
    .sign(key, hashes.SHA256())
)

with open(CRT_PATH, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"Created: {CRT_PATH}")
