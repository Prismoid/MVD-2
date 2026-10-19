import re
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import StreamingResponse
import httpx
import ssl
from pydantic import BaseModel
from datetime import datetime, timezone
import json, base64, hashlib, requests, time

from ecdsa import VerifyingKey

app = FastAPI()

# =====================================================
# HTTP Request Header Names
# =====================================================
AUTH_HEADER_NAMES = {
    "resource_id": "X-Resource-Id",
    "user_id": "X-User-Id",
    "expire_time": "X-Expire-Time",
    "signature": "X-Signature",
}

# =====================================================
# Helpers
# =====================================================
FC    = "http://host.docker.internal:7451"
PKR   = "http://host.docker.internal:7450"
AUTHZ = "http://host.docker.internal:7551"
# FILE_SERVER = "http://host.docker.internal:7552"
# GATEWAY = "http://host.docker.internal:7553"

def get_required_auth_headers(request: Request) -> dict:
    values = {}
    for key, header_name in AUTH_HEADER_NAMES.items():
        values[key] = request.headers.get(header_name)
        if values[key] is None:
            raise HTTPException(status_code=400, detail=f"missing required header: {header_name}")
    return values


def validate_expire(iso_time: str):
    t = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
    if t < datetime.now(timezone.utc):
        raise HTTPException(400, "expired")

def get_public_key(user_id: str) -> str:
    r = requests.get(f"{PKR}/pkr/get/{user_id}")
    if r.status_code != 200:
        raise HTTPException(400, "public key not found")
    return r.json()["public_key"]

def get_owner_user_id_from_fc(resource_id: str) -> str:
    r = requests.get(f"{FC}/fc/get", params={"resource_id": resource_id})
    if r.status_code != 200:
        raise HTTPException(400, "fc access failed")
    entries = r.json()
    if not entries:
        raise HTTPException(404, "resource_id not found")
    return entries[0]["user_id"]

def get_info_from_fc(resource_id: str) -> str:
    r = requests.get(f"{FC}/fc/get", params={"resource_id": resource_id})
    if r.status_code != 200:
        raise HTTPException(400, "fc access failed")
    entries = r.json()
    if not entries:
        raise HTTPException(404, "resource_id not found")
    return entries[0]["user_id"], entries[0]["endpoint"], entries[0]["resource_path"]

def check_authz(resource_id: str, user_id: str):
    r = requests.get(
        f"{AUTHZ}/authz/get",
        params={"resource_id": resource_id, "access_grantee_id": user_id},
    )
    if r.status_code != 200:
        raise HTTPException(403, "authz denied")

    valid_from = datetime.fromisoformat(r.json()["valid_from"]); valid_from = valid_from.replace(tzinfo=timezone.utc)
    expired_at = datetime.fromisoformat(r.json()["expired_at"]); expired_at = expired_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if not valid_from <= now < expired_at:
        raise HTTPException(403, "permission expired")

def verify_signature(public_key_pem: str, data: dict, signature_b64: str) -> bool:
    try:
        vk = VerifyingKey.from_pem(public_key_pem.encode())
        msg = json.dumps(data, sort_keys=True).encode()
        sig = base64.b64decode(signature_b64)
        return vk.verify(sig, msg, hashfunc=hashlib.sha256)
    except Exception:
        return False

def fill_resource_path(resource_path: str, request: Request) -> str:
    for key in re.findall(r"{([^{}]+)}", resource_path):
        value = request.query_params.get(key)
        if value is None:
            raise HTTPException(400, f"missing query parameter: {key}")
        resource_path = resource_path.replace(f"{{{key}}}", value)
    return resource_path

# リレー用関数
async def relay(req: Request, url: str):
    if req.url.query:
        url += f"?{req.url.query}"

    async with httpx.AsyncClient(timeout=30.0) as c:
        r = await c.request(
            req.method,
            url,
            headers={k: v for k, v in req.headers.items()
                     if k.lower() not in ("host", "content-length")},
            content=await req.body(),
        )

    return Response(r.content, r.status_code, headers=dict(r.headers))


# HTTPS用のリレー関数
async def relay_connector(req: Request, url: str, provider_id: str):
    if req.url.query:
        url += ("&" if "?" in url else "?") + req.url.query

    # PKRから相手Connectorの証明書を取得
    async with httpx.AsyncClient(timeout=10.0) as c:
        pkr_res = await c.get(f"{PKR}/pkr/get/{provider_id}")
        pkr_res.raise_for_status()

    # mTLS設定
    provider_cert = pkr_res.json()["certificate"]
    ctx = ssl.create_default_context(cadata=provider_cert)
    ctx.load_cert_chain("/certs/mtls.crt", "/certs/mtls.key")

    # HTTPSリレー
    async with httpx.AsyncClient(timeout=30.0, verify=ctx) as c:
        r = await c.request(
            req.method,
            url,
            headers={k: v for k, v in req.headers.items()
                     if k.lower() not in ("host", "content-length")},
            content=await req.body(),
        )

    headers = {k: v for k, v in r.headers.items()
               if k.lower() not in ("content-length", "content-encoding", "transfer-encoding", "connection")}
    return Response(r.content, r.status_code, headers=headers)

# =====================================================
# API
# =====================================================
# FC
@app.post("/fc/add")
async def fc_add(request: Request):
    return await relay(request, f"{FC}/fc/add")

@app.post("/fc/upd")
async def fc_upd(request: Request):
    return await relay(request, f"{FC}/fc/upd")

@app.post("/fc/del")
async def fc_del(request: Request):
    return await relay(request, f"{FC}/fc/del")

@app.get("/fc/get")
async def fc_get(request: Request):
    return await relay(request, f"{FC}/fc/get")

@app.get("/fc/debug/showAll")
async def fc_debug_show_all(request: Request):
    return await relay(request, f"{FC}/fc/debug/showAll")

@app.delete("/fc/debug/delAll")
async def fc_debug_delete_all(request: Request):
    return await relay(request, f"{FC}/fc/debug/delAll")


# PKR
@app.post("/pkr/add")
async def pkr_add(request: Request):
    return await relay(request, f"{PKR}/pkr/add")

@app.post("/pkr/upd")
async def pkr_upd(request: Request):
    return await relay(request, f"{PKR}/pkr/upd")

@app.post("/pkr/del")
async def pkr_del(request: Request):
    return await relay(request, f"{PKR}/pkr/del")

@app.get("/pkr/get/{user_id}")
async def pkr_get(user_id: str, request: Request):
    return await relay(request, f"{PKR}/pkr/get/{user_id}")

@app.get("/pkr/debug/showAllKeys")
async def pkr_debug_show_all(request: Request):
    return await relay(request, f"{PKR}/pkr/debug/showAllKeys")

@app.delete("/pkr/debug/delAllKeys")
async def pkr_debug_delete_all(request: Request):
    return await relay(request, f"{PKR}/pkr/debug/delAllKeys")


# AuthZ
@app.post("/authz/add")
async def authz_add(request: Request):
    return await relay(request, f"{AUTHZ}/authz/add")

@app.post("/authz/upd")
async def authz_upd(request: Request):
    return await relay(request, f"{AUTHZ}/authz/upd")

@app.post("/authz/del")
async def authz_del(request: Request):
    return await relay(request, f"{AUTHZ}/authz/del")

@app.get("/authz/get")
async def authz_get(request: Request):
    return await relay(request, f"{AUTHZ}/authz/get")

@app.get("/authz/debug/show_all")
async def authz_debug_show_all(request: Request):
    return await relay(request, f"{AUTHZ}/authz/debug/show_all")

@app.delete("/authz/debug/delete_all")
async def authz_debug_delete_all(request: Request):
    return await relay(request, f"{AUTHZ}/authz/debug/delete_all")

# =====================================================
# Connector Original API
# -----------------------
# The auth headers contain resource_id, user_id, expire_time, and signature.
# - resource_id : Target resource ID to be invoked
# - user_id     : ID of the requester
# - expire_time : Expiration time of the signed request
# - signature   : Signature for resource_id, user_id, and expire_time
# =====================================================
@app.api_route("/invoke_resource", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def invoke_resource(request: Request):
    auth_headers = get_required_auth_headers(request)
    user_id, endpoint, resource_path = get_info_from_fc(auth_headers["resource_id"])
    url = f"{endpoint.rstrip('/')}/relay_resource"
    # httpsなら暗号化通信
    if endpoint.startswith("https://"):
        return await relay_connector(request, url, user_id)
    return await relay(request, url)

@app.api_route("/relay_resource", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def relay_resource(request: Request):
    auth_headers = get_required_auth_headers(request)
    pubkey = get_public_key(auth_headers["user_id"])
    signed_data = {
        "resource_id": auth_headers["resource_id"],
        "user_id": auth_headers["user_id"],
        "expire_time": auth_headers["expire_time"],
    }
    print("signed_data:", signed_data, flush=True)
    print("signature:", auth_headers["signature"], flush=True)
    print("pubkey:", pubkey, flush=True)
    print("verified:", verify_signature(pubkey, signed_data, auth_headers["signature"]), flush=True)
    if not verify_signature(pubkey, signed_data, auth_headers["signature"]):
        raise HTTPException(400, "invalid signature")

    check_authz(auth_headers["resource_id"], auth_headers["user_id"])

    # resource_pathの取得
    user_id, endpoint, resource_path = get_info_from_fc(auth_headers["resource_id"])
    resource_path = fill_resource_path(resource_path, request)
    return await relay(request, resource_path)
