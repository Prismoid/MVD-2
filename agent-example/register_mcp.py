import base64, hashlib, json
from datetime import datetime, timedelta, timezone

import requests
from ecdsa import SigningKey


RESOURCE_ID = "mcp-server"
USER_CONNECTOR_URL = "http://localhost:7550"
PROVIDER_CONNECTOR_URL = "http://localhost:7650"
PROVIDER_CONNECTOR_URL_WITH_TLS = "https://host.docker.internal:7653"

MCP_URL = "http://host.docker.internal:32500/mcp"
USER_ID = "user" # AI agent
PROVIDER_ID = "provider" # owner

USER_PRIVATE_KEY = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqYxhjDxzVZv0AFFMAfvHC8iKpXmbckDATOMZuz/9K1oAoGCCqGSM49
AwEHoUQDQgAEz86DFhgDHZoLF/i4EZI9usUZR257wVqeoEsm9YIafEBeNQ0r5zxF
WpCJLab/1JIEsTpz+1Ml1oY3iqwkJ1IAwQ==
-----END EC PRIVATE KEY-----
"""

USER_X509 = """-----BEGIN CERTIFICATE-----
MIIBTzCB9qADAgECAhQBhYVVES9yz/zUOq8MOFLQDM8UPDAKBggqhkjOPQQDAjAP
MQ0wCwYDVQQDDAR1c2VyMCAXDTI2MTAxMzA0MzcyNVoYDzk5OTkxMjMxMjM1OTU5
WjAPMQ0wCwYDVQQDDAR1c2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj9aR
sYSVNPP2oVI42V06nnIO0PLOhRepcr8IpUJHKNSVueaXUswfaoXaxu2NHWzQBwx2
DNL6NC+OLGeClob99qMuMCwwKgYDVR0RBCMwIYIJbG9jYWxob3N0ghRob3N0LmRv
Y2tlci5pbnRlcm5hbDAKBggqhkjOPQQDAgNIADBFAiEA9tfygHaWFGhUFAt8XEnX
NRC/jUKl3xCS3mLgY41w4r4CICwt2MtBC20vZ7iFY/wMhANjjaprykD9crHkOvmG
2xI+
-----END CERTIFICATE-----"""

PROVIDER_PRIVATE_KEY = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPGDOSE243K+HYxR3v90wTtxuL4RCCXnWyxuZBCNVWWSoAoGCCqGSM49
AwEHoUQDQgAE1jieijJUvH/VvlwfWfiXRTOzl6Olj1njD1Ou2ja9YlpZOEFuLm5+
QNzA2vEEMCk29ZMb40agwHauarV/Y8rOmQ==
-----END EC PRIVATE KEY-----
"""

PROVIDER_X509 = """-----BEGIN CERTIFICATE-----
MIIBVzCB/qADAgECAhRF+Cx5wa6Z2pTh4jaO1jMgkoXFgDAKBggqhkjOPQQDAjAT
MREwDwYDVQQDDAhwcm92aWRlcjAgFw0yNjEwMTkwNjQyNTFaGA85OTk5MTIzMTIz
NTk1OVowEzERMA8GA1UEAwwIcHJvdmlkZXIwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAATlJsso+uT9iFw+RL9Q/8LzBgxSXDS4iUdAX48illYHfRyk7Zl0lbzlLpav
HhCTYQM/pRlOrIuzZiwE8+fyPSnooy4wLDAqBgNVHREEIzAhgglsb2NhbGhvc3SC
FGhvc3QuZG9ja2VyLmludGVybmFsMAoGCCqGSM49BAMCA0gAMEUCIQDweQJWaYFp
Y91WnhR42WOb53OX0GFwerUWnUmfktDmwgIgNBlAA0e0kAI+mIpApvt8/qSvG0YB
i82YvmYR8FHPzZY=
-----END CERTIFICATE-----"""

def expires(minutes=5, hours=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes, hours=hours)).isoformat().replace("+00:00", "Z")


def sign(sk, data):
    msg = json.dumps(data, sort_keys=True).encode()
    return base64.b64encode(sk.sign(msg, hashfunc=hashlib.sha256)).decode()


def signed(sk, data):
    data["signature"] = sign(sk, data)
    return data


def post(connector_url, path, payload):
    r = requests.post(connector_url + path, json=payload)
    print(path, r.status_code, r.text)
    r.raise_for_status()


sk_user = SigningKey.from_pem(USER_PRIVATE_KEY)
sk_provider = SigningKey.from_pem(PROVIDER_PRIVATE_KEY)

# Repeatable PoC: clear previous registrations.
requests.delete(USER_CONNECTOR_URL + "/pkr/debug/delAllKeys")
requests.delete(USER_CONNECTOR_URL + "/fc/debug/delAll")
requests.delete(USER_CONNECTOR_URL + "/authz/debug/delete_all")
requests.delete(PROVIDER_CONNECTOR_URL + "/authz/debug/delete_all")

post(USER_CONNECTOR_URL, "/pkr/add", signed(sk_user, {
    "user_id": USER_ID,
    "public_key": sk_user.verifying_key.to_pem().decode(),
    "certificate": USER_X509,
    "expire_time": expires(),
}))

post(PROVIDER_CONNECTOR_URL, "/pkr/add", signed(sk_provider, {
    "user_id": PROVIDER_ID,
    "public_key": sk_provider.verifying_key.to_pem().decode(),
    "certificate": PROVIDER_X509,
    "expire_time": expires(),
}))

post(PROVIDER_CONNECTOR_URL, "/fc/add", signed(sk_provider, {
    "resource_id": RESOURCE_ID,
    "user_id": PROVIDER_ID,
    "description": "mcp test",
    "endpoint": PROVIDER_CONNECTOR_URL_WITH_TLS,
    "resource_path": MCP_URL,
    "expire_time": expires(),
}))

post(PROVIDER_CONNECTOR_URL, "/authz/add", signed(sk_provider, {
    "resource_id": RESOURCE_ID,
    "access_grantee_id": USER_ID,
    "valid_from": expires(minutes=0, hours=0),
    "expired_at": expires(hours=1),
    "expire_time": expires(),
}))

print("registered:", RESOURCE_ID, "->", MCP_URL)
