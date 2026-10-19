import requests
import json
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from ecdsa import SigningKey, NIST256p

# =====================================================
# config
# =====================================================
PKR_URL = "http://localhost:7450"
CAT_URL = "http://localhost:7451"

USER_A = "userA"
USER_B = "userB"
RESOURCE_ID = "resource-001"

# =====================================================
# key (PoC)
# =====================================================
sk_a = SigningKey.generate(curve=NIST256p)
vk_a = sk_a.get_verifying_key()
pub_a = vk_a.to_pem().decode()

sk_b = SigningKey.generate(curve=NIST256p)
vk_b = sk_b.get_verifying_key()
pub_b = vk_b.to_pem().decode()

# =====================================================
# utils
# =====================================================
def iso_now_plus(mins=5):
    return (
        datetime.now(timezone.utc) + timedelta(minutes=mins)
    ).isoformat().replace("+00:00", "Z")


def sign(sk: SigningKey, data: dict) -> str:
    msg = json.dumps(data, sort_keys=True).encode()
    sig = sk.sign(msg, hashfunc=hashlib.sha256)
    return base64.b64encode(sig).decode()


def show(res: requests.Response):
    ct = res.headers.get("content-type", "")
    print(res.status_code)
    if "application/json" in ct:
        try:
            print(json.dumps(res.json(), indent=2))
            return
        except Exception:
            pass
    print(res.text)

# =====================================================
# PKR test
# =====================================================
print("=== PKR: debug delete all ===")
show(requests.delete(f"{PKR_URL}/pkr/debug/delAllKeys"))

print("\n=== PKR: register userA key ===")
payload = {
    "user_id": USER_A,
    "public_key": pub_a,
    "expire_time": iso_now_plus(),
}
show(
    requests.post(
        f"{PKR_URL}/pkr/add",
        json={**payload, "signature": sign(sk_a, payload)},
    )
)

print("\n=== PKR: register userB key ===")
payload = {
    "user_id": USER_B,
    "public_key": pub_b,
    "expire_time": iso_now_plus(),
}
show(
    requests.post(
        f"{PKR_URL}/pkr/add",
        json={**payload, "signature": sign(sk_b, payload)},
    )
)

# =====================================================
# Federated Catalog test
# =====================================================
print("\n=== CAT: debug delete all ===")
show(requests.delete(f"{CAT_URL}/fc/debug/delAll"))

print("\n=== CAT: add catalog entry (owner = userA) ===")
cat_add = {
    "resource_id": RESOURCE_ID,
    "user_id": USER_A,
    "description": "sample climate dataset for PoC",
    "endpoint": "https://example.com/connector",
    "resource_path": "/resource/climate",
    "expire_time": iso_now_plus(),
}
show(
    requests.post(
        f"{CAT_URL}/fc/add",
        json={**cat_add, "signature": sign(sk_a, cat_add)},
    )
)

print("\n=== CAT: update catalog (transfer owner userA → userB, dual signatures) ===")
cat_upd = {
    "resource_id": RESOURCE_ID,
    "user_id": USER_B,  # new owner
    "description": "updated description (owner transferred)",
    "endpoint": "https://example.com/connector",
    "resource_path": "/resource/climate/v2",
    "expire_time": iso_now_plus(),
}

signature_old = sign(sk_a, cat_upd)  # old owner (userA)
signature_new = sign(sk_b, cat_upd)  # new owner (userB)

show(
    requests.post(
        f"{CAT_URL}/fc/upd",
        json={
            **cat_upd,
            "signature_old": signature_old,
            "signature_new": signature_new,
        },
    )
)

print("\n=== CAT: get catalog after update (all) ===")
show(requests.get(f"{CAT_URL}/fc/get"))

print("\n=== CAT: get catalog by resource_id ===")
show(requests.get(f"{CAT_URL}/fc/get", params={"resource_id": RESOURCE_ID}))

print("\n=== CAT: get catalog by user_id ===")
show(requests.get(f"{CAT_URL}/fc/get", params={"user_id": USER_B}))

print("\n=== CAT: get catalog by keyword ===")
show(requests.get(f"{CAT_URL}/fc/get", params={"keyword": "climate"}))

print("\n=== CAT: get catalog by resource_id + user_id ===")
show(
    requests.get(
        f"{CAT_URL}/fc/get",
        params={"resource_id": RESOURCE_ID, "user_id": USER_B},
    )
)

print("\n=== CAT: delete catalog entry (owner = userB) ===")
cat_del = {
    "resource_id": RESOURCE_ID,
    "expire_time": iso_now_plus(),
}
show(
    requests.post(
        f"{CAT_URL}/fc/del",
        json={**cat_del, "signature": sign(sk_b, cat_del)},
    )
)

print("\n=== CAT: get after delete (debug showAll) ===")
show(requests.get(f"{CAT_URL}/fc/debug/showAll"))
