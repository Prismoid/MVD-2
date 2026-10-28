import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

import requests
from ecdsa import NIST256p, SigningKey

# =====================================================
# config
# =====================================================
CONNECTOR_URL = "http://localhost:7550"
GATEWAY_URL = "https://localhost:7553"
SELF_ENDPOINT = "https://host.docker.internal:7553"  # apiコンテナから見た自分のGateway
CERT_DIR = Path(__file__).resolve().parent.parent / "certs"
USER_CERT = CERT_DIR / "mtls.crt"
USER_KEY = CERT_DIR / "mtls.key"
certificate = USER_CERT.read_text()
USER_A = x509.load_pem_x509_certificate(certificate.encode()).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
USER_B = "user"
RESOURCE_ID = "resource-001"
RESOURCE_PATH = "http://host.docker.internal:7552/hello_world.txt"

# main.py の AUTH_HEADER_NAMES に合わせる
AUTH_HEADER_NAMES = {
    "resource_id": "X-Resource-Id",
    "user_id": "X-User-Id",
    "expire_time": "X-Expire-Time",
    "signature": "X-Signature",
}

# =====================================================
# utils
# =====================================================
def iso_now_plus(mins: int = 5, hours: int = 0) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(minutes=mins, hours=hours)
    ).isoformat().replace("+00:00", "Z")

def iso_now_minus(mins: int = 5, hours: int = 0) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(minutes=mins, hours=hours)
    ).isoformat().replace("+00:00", "Z")


def sign(sk: SigningKey, data: dict) -> str:
    msg = json.dumps(data, sort_keys=True).encode()
    sig = sk.sign(msg, hashfunc=hashlib.sha256)
    return base64.b64encode(sig).decode()


def show(label: str, res: requests.Response):
    print(f"{label} -> {res.status_code}")
    try:
        print(json.dumps(res.json(), indent=2, ensure_ascii=False))
    except Exception:
        print(res.text)
    print("-" * 60)


def build_auth_headers(sk: SigningKey, resource_id: str, user_id: str) -> dict:
    signed_data = {
        "resource_id": resource_id,
        "user_id": user_id,
        "expire_time": iso_now_plus(),
    }
    signed_data["signature"] = sign(sk, signed_data)

    return {
        AUTH_HEADER_NAMES["resource_id"]: signed_data["resource_id"],
        AUTH_HEADER_NAMES["user_id"]: signed_data["user_id"],
        AUTH_HEADER_NAMES["expire_time"]: signed_data["expire_time"],
        AUTH_HEADER_NAMES["signature"]: signed_data["signature"],
    }


# =====================================================
# keys (PoC)
# =====================================================
sk_a = SigningKey.from_pem(USER_KEY.read_text())
pub_a = sk_a.get_verifying_key().to_pem().decode()

sk_b = sk_a
pub_b = pub_a

# =====================================================
# 0. DEBUG delete_all
# =====================================================
show("PKR delete_all", requests.delete(f"{CONNECTOR_URL}/pkr/debug/delAllKeys"))
show("FC delete_all", requests.delete(f"{CONNECTOR_URL}/fc/debug/delAll"))
show("AuthZ delete_all", requests.delete(f"{CONNECTOR_URL}/authz/debug/delete_all"))

# =====================================================
# 1. PKR: register userA
# =====================================================
payload = {
    "user_id": USER_A,
    "public_key": pub_a,
    "certificate": certificate,
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_a, payload)

show(
    "PKR add userA",
    requests.post(f"{CONNECTOR_URL}/pkr/add", json=payload),
)

# =====================================================
# 3. FC: add resource-001 (owner=userA)
# =====================================================
payload = {
    "resource_id": RESOURCE_ID,
    "user_id": USER_A,
    "description": "minimal PoC mTLS self-connection",
    "endpoint": SELF_ENDPOINT,
    "resource_path": RESOURCE_PATH,
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_a, payload)

show(
    "FC add resource-001",
    requests.post(f"{CONNECTOR_URL}/fc/add", json=payload),
)

time.sleep(0.5)

# =====================================================
# 4. AuthZ: grant user (signed by user)
# =====================================================
payload = {
    "resource_id": RESOURCE_ID,
    "access_grantee_id": USER_B,
    "valid_from": iso_now_minus(hours=1),
    "expired_at": iso_now_plus(hours=1),
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_a, payload)

show(
    "AuthZ add (grant userB)",
    requests.post(f"{CONNECTOR_URL}/authz/add", json=payload),
)

# =====================================================
# 5. AuthZ: get (確認)
# =====================================================
r = requests.get(
    f"{CONNECTOR_URL}/authz/get",
    params={
        "resource_id": RESOURCE_ID,
        "access_grantee_id": USER_B,
    },
)

show("AuthZ get", r)

# =====================================================
# 6. Gateway: mTLS確認（証明書あり=成功、なし=失敗）
# =====================================================
r = requests.get(
    f"{GATEWAY_URL}/openapi.json",
    verify=str(USER_CERT),
    cert=(str(USER_CERT), str(USER_KEY)),
    timeout=10,
)
show("Gateway mTLS with certificate", r)
r.raise_for_status()

try:
    r = requests.get(f"{GATEWAY_URL}/openapi.json", verify=str(USER_CERT), timeout=10)
except requests.exceptions.SSLError:
    print("Gateway without client certificate -> rejected (OK)")
else:
    raise RuntimeError(f"Gateway accepted a request without client certificate: {r.status_code}")

# =====================================================
# 7. invoke_resource (signed by userB)
#     自分のHTTP Connector → 自分のHTTPS Gateway → 自分のConnector
# =====================================================
headers = build_auth_headers(sk_b, RESOURCE_ID, USER_B)
r = requests.get(
    f"{CONNECTOR_URL}/invoke_resource",
    headers=headers,
    stream=True,
)

print("invoke_resource ->", r.status_code)
if r.status_code != 200:
    print(r.text)
    raise SystemExit(1)

print(r.text)

print("Self mTLS Connector test -> PASS")
