import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import requests
from ecdsa import NIST256p, SigningKey

PKR_URL = "http://localhost:7450"
CAT_URL = "http://localhost:7451"

USER_IDS = [
    "userA", "userB", "userC", "userD", "userE", "userF",
    "userG", "userH", "userI", "userJ", "userK", "userL",
]

RESOURCE_TEMPLATES = [
    ("climate-dataset", "regional climate observation dataset", "/resource/climate/observations"),
    ("temperature-api", "temperature sensor API", "/api/v1/sensors/temperature"),
    ("humidity-api", "humidity sensor API", "/api/v1/sensors/humidity"),
    ("co2-api", "CO2 concentration monitoring API", "/api/v1/sensors/co2"),
    ("hvac-metadata", "air conditioner metadata", "/api/v1/hvac/airconditioner/metadata"),
    ("hvac-status", "air conditioner operation status", "/api/v1/hvac/airconditioner/status"),
    ("fems-energy", "factory energy management data", "/resource/fems/energy"),
    ("fems-power", "factory power consumption stream", "/resource/fems/power"),
    ("aas-submodel", "asset administration shell submodel", "/aas/submodels/001"),
    ("aas-nameplate", "AAS digital nameplate data", "/aas/submodels/nameplate"),
    ("erp-order", "ERP order management sample", "/api/v1/erp/orders"),
    ("erp-inventory", "ERP inventory sample", "/api/v1/erp/inventory"),
    ("logistics-trace", "logistics traceability events", "/api/v1/logistics/traces"),
    ("production-plan", "production planning schedule", "/api/v1/factory/production-plan"),
]


def iso_now_plus(mins=60):
    return (
        datetime.now(timezone.utc) + timedelta(minutes=mins)
    ).isoformat().replace("+00:00", "Z")


def sign(sk: SigningKey, data: dict) -> str:
    msg = json.dumps(data, sort_keys=True).encode()
    sig = sk.sign(msg, hashfunc=hashlib.sha256)
    return base64.b64encode(sig).decode()


def show(title, res):
    print(f"\n=== {title} ===")
    print(res.status_code)
    print(res.text)


def make_users():
    users = {}
    for user_id in USER_IDS:
        sk = SigningKey.generate(curve=NIST256p)
        vk = sk.get_verifying_key()
        users[user_id] = {
            "sk": sk,
            "public_key": vk.to_pem().decode(),
        }
    return users


def make_catalog_entries():
    entries = []
    resource_no = 1

    # 42 entries: enough to check multiple pages with PAGE_SIZE=10.
    for round_no in range(3):
        for name, description, resource_path in RESOURCE_TEMPLATES:
            user_id = USER_IDS[(resource_no - 1) % len(USER_IDS)]
            connector_no = ((resource_no - 1) % 4) + 1
            entries.append({
                "resource_id": f"resource-{resource_no:03d}",
                "user_id": user_id,
                "description": f"{description} for PoC #{round_no + 1}",
                "endpoint": f"https://example.com/connector-{connector_no}",
                "resource_path": f"{resource_path}/{round_no + 1}",
            })
            resource_no += 1

    return entries


users = make_users()

# =====================================================
# reset
# =====================================================
show("PKR: delete all", requests.delete(f"{PKR_URL}/pkr/debug/delAllKeys"))
show("CAT: delete all", requests.delete(f"{CAT_URL}/fc/debug/delAll"))


# =====================================================
# add public keys
# =====================================================
for user_id, key_info in users.items():
    payload = {
        "user_id": user_id,
        "public_key": key_info["public_key"],
        "expire_time": iso_now_plus(),
    }

    res = requests.post(
        f"{PKR_URL}/pkr/add",
        json={**payload, "signature": sign(key_info["sk"], payload)},
    )

    show(f"PKR: add {user_id}", res)


# =====================================================
# add catalog entries
# =====================================================
catalog_entries = make_catalog_entries()

for entry in catalog_entries:
    payload = {
        **entry,
        "expire_time": iso_now_plus(),
    }

    sk = users[entry["user_id"]]["sk"]

    res = requests.post(
        f"{CAT_URL}/fc/add",
        json={**payload, "signature": sign(sk, payload)},
    )

    show(f"CAT: add {entry['resource_id']}", res)


# =====================================================
# check
# =====================================================
show("CAT: get all", requests.get(f"{CAT_URL}/fc/get"))
show("PKR: show all", requests.get(f"{PKR_URL}/pkr/debug/showAllKeys"))

print("\n=== summary ===")
print(f"PKR users: {len(users)}")
print(f"FC entries: {len(catalog_entries)}")
