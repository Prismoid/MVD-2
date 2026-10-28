from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

KEY_PATH = "mtls.key"

key = ec.generate_private_key(
    ec.SECP256R1()
)

with open(KEY_PATH, "wb") as f:
    f.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

print(f"Created: {KEY_PATH}")
