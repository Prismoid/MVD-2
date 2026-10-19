import requests, json, base64, hashlib
from datetime import datetime, timezone, timedelta
from ecdsa import SigningKey, NIST256p

# =====================================================
# config
# =====================================================
BASE_URL = "http://localhost:7450"
USER_ID = "userA"

# =====================================================
# key (PoC)
# =====================================================
# --- old key ---
sk_old = SigningKey.generate(curve=NIST256p)
vk_old = sk_old.get_verifying_key()
public_key_old = vk_old.to_pem().decode()

# --- new key ---
sk_new = SigningKey.generate(curve=NIST256p)
vk_new = sk_new.get_verifying_key()
public_key_new = vk_new.to_pem().decode()

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

# -----------------------------------------------------
print("\n=== PKR: register key (old key) ===")
add_payload = {
    "user_id": USER_ID,
    "public_key": public_key_old,
    "expire_time": iso_now_plus(),
}
add_sig = sign(sk_old, add_payload)

res = requests.post(
    f"{BASE_URL}/pkr/add",
    json={**add_payload, "signature": add_sig},
)
print(res.status_code, res.text)

# -----------------------------------------------------
print("\n=== PKR: get key (should be old key) ===")
res = requests.get(f"{BASE_URL}/pkr/get/{USER_ID}")
print(res.status_code)
print(res.text)

# -----------------------------------------------------
print("\n=== PKR: update key (old -> new) ===")
upd_payload = {
    "user_id": USER_ID,
    "new_public_key": public_key_new,
    "expire_time": iso_now_plus(),
}
upd_sig = sign(sk_old, upd_payload)   # ★ 旧鍵で署名

res = requests.post(
    f"{BASE_URL}/pkr/upd",
    json={**upd_payload, "signature": upd_sig},
)
print(res.status_code, res.text)

# -----------------------------------------------------
print("\n=== PKR: get key (should be new key) ===")
res = requests.get(f"{BASE_URL}/pkr/get/{USER_ID}")
print(res.status_code)
print(res.text)

# -----------------------------------------------------
print("\n=== PKR: delete key (signed by new key) ===")
del_payload = {
    "user_id": USER_ID,
    "expire_time": iso_now_plus(),
}
del_sig = sign(sk_new, del_payload)   # ★ 更新後は new key

res = requests.post(
    f"{BASE_URL}/pkr/del",
    json={**del_payload, "signature": del_sig},
)
print(res.status_code, res.text)

# -----------------------------------------------------
print("\n=== PKR: get after delete ===")
res = requests.get(f"{BASE_URL}/pkr/get/{USER_ID}")
print(res.status_code, res.text)
