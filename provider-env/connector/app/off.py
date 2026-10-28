import base64
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

import requests
from ecdsa import NIST256p, SigningKey

# =====================================================
# config
# =====================================================
CONNECTOR_URL = "http://localhost:7550"

USER_A = "userA"
USER_B = "userB"
RESOURCE_ID = "resource-001"
RESOURCE_PATH = "http://172.26.16.25:8000/api/v1/lighting/{light_id}/off"

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
sk_a = SigningKey.generate(curve=NIST256p)
pub_a = sk_a.get_verifying_key().to_pem().decode()

sk_b = SigningKey.generate(curve=NIST256p)
pub_b = sk_b.get_verifying_key().to_pem().decode()

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
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_a, payload)

show(
    "PKR add userA",
    requests.post(f"{CONNECTOR_URL}/pkr/add", json=payload),
)

# =====================================================
# 2. PKR: register userB
# =====================================================
payload = {
    "user_id": USER_B,
    "public_key": pub_b,
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_b, payload)

show(
    "PKR add userB",
    requests.post(f"{CONNECTOR_URL}/pkr/add", json=payload),
)

# =====================================================
# 3. FC: add resource-001 (owner=userA)
# =====================================================
payload = {
    "resource_id": RESOURCE_ID,
    "user_id": USER_A,
    "description": "minimal PoC HTTP resource",
    "endpoint": "http://host.docker.internal:7550",
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
# 4. AuthZ: grant userB (signed by userA)
# =====================================================
payload = {
    "resource_id": RESOURCE_ID,
    "access_grantee_id": USER_B,
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
# 6. invoke_resource (signed by userB)
# =====================================================
headers = build_auth_headers(sk_b, RESOURCE_ID, USER_B)

r = requests.post(
    f"{CONNECTOR_URL}/invoke_resource",
    headers=headers,
    params={"light_id": "a302-1"},
    auth=("admin", "admin"), # Basic認証用のユーザ名/パスワードは変える
    stream=True,
)

print("invoke_resource ->", r.status_code)
if r.status_code != 200:
    print(r.text)
    raise SystemExit(1)

print(r.text)
