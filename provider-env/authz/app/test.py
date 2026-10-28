import requests
import json
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from ecdsa import SigningKey, NIST256p

# =====================================================
# config
# =====================================================
PKR_URL   = "http://localhost:7450"
FC_URL    = "http://localhost:7451"
AUTHZ_URL = "http://localhost:7551"

USER_A = "userA"
USER_B = "userB"
RESOURCE_ID = "resource-001"

# =====================================================
# utils
# =====================================================
def iso_now_plus(mins=5, hours=0):
    return (
        datetime.now(timezone.utc) + timedelta(minutes=mins, hours=hours)
    ).isoformat().replace("+00:00", "Z")

def sign(sk: SigningKey, data: dict) -> str:
    msg = json.dumps(data, sort_keys=True).encode()
    sig = sk.sign(msg, hashfunc=hashlib.sha256)
    return base64.b64encode(sig).decode()

def show(label, res: requests.Response):
    print(f"{label} -> {res.status_code}")
    try:
        print(json.dumps(res.json(), indent=2))
    except Exception:
        print(res.text)
    print("-" * 50)

# =====================================================
# keys (PoC)
# =====================================================
sk_a = SigningKey.generate(curve=NIST256p)
pub_a = sk_a.get_verifying_key().to_pem().decode()

# =====================================================
# 0. DEBUG delete_all
# =====================================================
show("PKR delete_all",  requests.delete(f"{PKR_URL}/pkr/debug/delAllKeys"))
show("FC  delete_all",  requests.delete(f"{FC_URL}/fc/debug/delAll"))
show("AuthZ delete_all",requests.delete(f"{AUTHZ_URL}/authz/debug/delete_all"))

# =====================================================
# 1. PKR: register userA
# =====================================================
payload = {
    "user_id": USER_A,
    "public_key": pub_a,
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_a, payload)
show("PKR add userA", requests.post(f"{PKR_URL}/pkr/add", json=payload))

# =====================================================
# 2. FC: add resource-001 (owner=userA)
# =====================================================
payload = {
    "resource_id": RESOURCE_ID,
    "user_id": USER_A,
    "description": "minimal PoC resource",
    "endpoint": "https://example.com",
    "resource_path": "/resource/sample",
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_a, payload)
show("FC add resource-001", requests.post(f"{FC_URL}/fc/add", json=payload))

# =====================================================
# 3. AuthZ: grant userB (signed by userA)
# =====================================================
payload = {
    "resource_id": RESOURCE_ID,
    "access_grantee_id": USER_B,
    "expired_at": iso_now_plus(hours=1),
    "expire_time": iso_now_plus(),
}
payload["signature"] = sign(sk_a, payload)
show("AuthZ add (grant userB)", requests.post(f"{AUTHZ_URL}/authz/add", json=payload))

# =====================================================
# 4. AuthZ: get (確認)
# =====================================================
r = requests.get(
    f"{AUTHZ_URL}/authz/get",
    params={"resource_id": RESOURCE_ID, "access_grantee_id": USER_B},
)
show("AuthZ get", r)
