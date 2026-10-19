import requests, json, base64, hashlib
from datetime import datetime, timezone, timedelta
from ecdsa import SigningKey, NIST256p
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import sys

# =====================================================
# config
# =====================================================
BASE_URL = "http://localhost:7450"
USER_ID = "userA"

# =====================================================
# key / certificate (PoC)
# =====================================================
def make_cert(sk: SigningKey, user_id: str) -> str:
    key = serialization.load_pem_private_key(sk.to_pem(), None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, user_id)])

    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
        .decode()
    )

sk_old = SigningKey.generate(curve=NIST256p)
public_key_old = sk_old.get_verifying_key().to_pem().decode()
certificate_old = make_cert(sk_old, USER_ID)

sk_new = SigningKey.generate(curve=NIST256p)
public_key_new = sk_new.get_verifying_key().to_pem().decode()
certificate_new = make_cert(sk_new, USER_ID)

def iso_now_plus(mins=5):
    return (
        datetime.now(timezone.utc) + timedelta(minutes=mins)
    ).isoformat().replace("+00:00", "Z")

def sign(sk: SigningKey, data: dict) -> str:
    msg = json.dumps(data, sort_keys=True).encode()
    sig = sk.sign(msg, hashfunc=hashlib.sha256)
    return base64.b64encode(sig).decode()

# =====================================================
# test
# =====================================================
print("=== PKR: debug delete all ===")
res = requests.delete(f"{BASE_URL}/pkr/debug/delAllKeys")
print(res.status_code, res.text)

print("\n=== PKR: register key + certificate (old) ===")
add_payload = {
    "user_id": USER_ID,
    "public_key": public_key_old,
    "certificate": certificate_old,
    "expire_time": iso_now_plus(),
}
res = requests.post(
    f"{BASE_URL}/pkr/add",
    json={**add_payload, "signature": sign(sk_old, add_payload)},
)
print(res.status_code, res.text)

print("\n=== PKR: get (should be old) ===")
res = requests.get(f"{BASE_URL}/pkr/get/{USER_ID}")
print(res.status_code)
print(res.text)

print("\n=== PKR: update key + certificate (old -> new) ===")
upd_payload = {
    "user_id": USER_ID,
    "new_public_key": public_key_new,
    "new_certificate": certificate_new,
    "expire_time": iso_now_plus(),
}
res = requests.post(
    f"{BASE_URL}/pkr/upd",
    json={**upd_payload, "signature": sign(sk_old, upd_payload)},
)
print(res.status_code, res.text)

print("\n=== PKR: get (should be new) ===")
res = requests.get(f"{BASE_URL}/pkr/get/{USER_ID}")
print(res.status_code)
print(res.text)

print("\n=== PKR: delete (signed by new key) ===")
del_payload = {
    "user_id": USER_ID,
    "expire_time": iso_now_plus(),
}
sys.exit(-1)
res = requests.post(
    f"{BASE_URL}/pkr/del",
    json={**del_payload, "signature": sign(sk_new, del_payload)},
)
print(res.status_code, res.text)

print("\n=== PKR: get after delete ===")
res = requests.get(f"{BASE_URL}/pkr/get/{USER_ID}")
print(res.status_code, res.text)
