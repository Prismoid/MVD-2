import base64, hashlib, json
from datetime import datetime, timedelta, timezone

import requests
from ecdsa import SigningKey


RESOURCE_ID = "mcp-server"
CONNECTOR_URL = "http://localhost:7550"
MCP_URL = "http://host.docker.internal:32500/mcp"
USER_A = "userA"  # owner
USER_B = "userB"  # AI agent

USER_A_PRIVATE_KEY = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqYxhjDxzVZv0AFFMAfvHC8iKpXmbckDATOMZuz/9K1oAoGCCqGSM49
AwEHoUQDQgAEz86DFhgDHZoLF/i4EZI9usUZR257wVqeoEsm9YIafEBeNQ0r5zxF
WpCJLab/1JIEsTpz+1Ml1oY3iqwkJ1IAwQ==
-----END EC PRIVATE KEY-----
"""

USER_B_PRIVATE_KEY = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPGDOSE243K+HYxR3v90wTtxuL4RCCXnWyxuZBCNVWWSoAoGCCqGSM49
AwEHoUQDQgAE1jieijJUvH/VvlwfWfiXRTOzl6Olj1njD1Ou2ja9YlpZOEFuLm5+
QNzA2vEEMCk29ZMb40agwHauarV/Y8rOmQ==
-----END EC PRIVATE KEY-----
"""


def expires(minutes=5, hours=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes, hours=hours)).isoformat().replace("+00:00", "Z")


def sign(sk, data):
    msg = json.dumps(data, sort_keys=True).encode()
    return base64.b64encode(sk.sign(msg, hashfunc=hashlib.sha256)).decode()


def signed(sk, data):
    data["signature"] = sign(sk, data)
    return data


def post(path, payload):
    r = requests.post(CONNECTOR_URL + path, json=payload)
    print(path, r.status_code, r.text)
    r.raise_for_status()


sk_a = SigningKey.from_pem(USER_A_PRIVATE_KEY)
sk_b = SigningKey.from_pem(USER_B_PRIVATE_KEY)

# Repeatable PoC: clear previous registrations.
requests.delete(CONNECTOR_URL + "/pkr/debug/delAllKeys")
requests.delete(CONNECTOR_URL + "/fc/debug/delAll")
requests.delete(CONNECTOR_URL + "/authz/debug/delete_all")

post("/pkr/add", signed(sk_a, {
    "user_id": USER_A,
    "public_key": sk_a.verifying_key.to_pem().decode(),
    "expire_time": expires(),
}))

post("/pkr/add", signed(sk_b, {
    "user_id": USER_B,
    "public_key": sk_b.verifying_key.to_pem().decode(),
    "expire_time": expires(),
}))

post("/fc/add", signed(sk_a, {
    "resource_id": RESOURCE_ID,
    "user_id": USER_A,
    "description": "mcp test",
    "endpoint": CONNECTOR_URL,
    "resource_path": MCP_URL,
    "expire_time": expires(),
}))

post("/authz/add", signed(sk_a, {
    "resource_id": RESOURCE_ID,
    "access_grantee_id": USER_B,
    "expired_at": expires(hours=1),
    "expire_time": expires(),
}))

print("registered:", RESOURCE_ID, "->", MCP_URL)
