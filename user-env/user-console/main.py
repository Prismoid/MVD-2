import base64
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from ecdsa import NIST256p, SigningKey
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

CONNECTOR_URL = os.getenv("CONNECTOR_URL", "http://localhost:7550")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:7462/mvd_console")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class LocalKey(Base):
    __tablename__ = "local_keys"

    user_id = Column(String, primary_key=True)
    private_key = Column(String, nullable=False)
    public_key = Column(String, nullable=False)
    registered_at = Column(DateTime, nullable=False)


class UserReq(BaseModel):
    user_id: str


class PkrUserReq(BaseModel):
    user_id: str


class FcEntryReq(BaseModel):
    resource_id: str
    user_id: str
    description: str = ""
    endpoint: str
    resource_path: str


class FcDeleteReq(BaseModel):
    resource_id: str


class AuthzReq(BaseModel):
    user_id: str
    resource_id: str
    access_grantee_id: str
    expired_at: str


class AuthzDeleteReq(BaseModel):
    user_id: str
    resource_id: str
    access_grantee_id: str


class InvokeReq(BaseModel):
    resource_id: str
    user_id: str
    method: str = "GET"
    query_params: Optional[str] = None
    body: Optional[str] = None
    extra_headers: Optional[str] = None
    auth_type: str = "none"
    basic_user: Optional[str] = None
    basic_pass: Optional[str] = None
    bearer_token: Optional[str] = None
    custom_auth: Optional[str] = None


app = FastAPI(title="MVD Console")
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
def on_startup():
    for _ in range(20):
        try:
            Base.metadata.create_all(bind=engine)
            return
        except Exception:
            time.sleep(1)
    Base.metadata.create_all(bind=engine)


def iso_now_plus(minutes: int = 5) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat().replace("+00:00", "Z")


def new_key_pair() -> tuple[str, str]:
    sk = SigningKey.generate(curve=NIST256p)
    return sk.to_pem().decode(), sk.get_verifying_key().to_pem().decode()


def sign_payload(private_key_pem: str, payload: dict[str, Any]) -> str:
    sk = SigningKey.from_pem(private_key_pem.encode())
    msg = json.dumps(payload, sort_keys=True).encode()
    sig = sk.sign(msg, hashfunc=hashlib.sha256)
    return base64.b64encode(sig).decode()


def key_to_dict(k: LocalKey):
    return {
        "user_id": k.user_id,
        "private_key": k.private_key,
        "public_key": k.public_key,
        "registered_at": k.registered_at.isoformat(),
    }


def get_local_key_or_400(db, user_id: str) -> LocalKey:
    key = db.query(LocalKey).filter_by(user_id=user_id).first()
    if not key:
        raise HTTPException(400, f"local private key not found: {user_id}")
    return key


RESERVED_INVOKE_HEADERS = {
    "host",
    "content-length",
    "x-resource-id",
    "x-user-id",
    "x-expire-time",
    "x-signature",
    "authorization",
}


def parse_extra_headers(raw_headers: Optional[str]) -> dict[str, str]:
    """Parse optional HTTP headers for Invoke Resource.

    Supported formats:
    - One header per line: `Header-Name: value`
    - JSON object: `{"Header-Name": "value"}`

    Protocol/signature headers are reserved so the console cannot accidentally
    break the Connector signature verification path. Authorization is handled
    by the dedicated Authorization UI fields.
    """
    raw = (raw_headers or "").strip()
    if not raw:
        return {}

    if raw.startswith("{"):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"extra_headers JSON is invalid: {e.msg}")
        if not isinstance(parsed, dict):
            raise HTTPException(400, "extra_headers JSON must be an object")
        items = parsed.items()
    else:
        items = []
        for line_no, line in enumerate(raw.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise HTTPException(400, f"extra_headers line {line_no} must be 'Header-Name: value'")
            name, value = line.split(":", 1)
            items.append((name, value))

    headers: dict[str, str] = {}
    for name, value in items:
        header_name = str(name).strip()
        header_value = "" if value is None else str(value).strip()
        lower_name = header_name.lower()

        if not header_name:
            raise HTTPException(400, "header name must not be empty")
        if any(ch in header_name for ch in "\r\n:") or any(ch in header_value for ch in "\r\n"):
            raise HTTPException(400, "header name/value must not contain CR or LF")
        if lower_name in RESERVED_INVOKE_HEADERS:
            raise HTTPException(
                400,
                f"header '{header_name}' is reserved. Use the dedicated fields instead.",
            )

        headers[header_name] = header_value

    return headers


def build_authorization_header(req: InvokeReq) -> Optional[str]:
    auth_type = (req.auth_type or "none").strip().lower()

    if auth_type == "none":
        return None

    if auth_type == "basic":
        username = (req.basic_user or "").strip()
        password = req.basic_pass or ""
        if not username:
            raise HTTPException(400, "basic username is required")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return f"Basic {token}"

    if auth_type == "bearer":
        token = (req.bearer_token or "").strip()
        if not token:
            raise HTTPException(400, "bearer token is required")
        if token.lower().startswith("bearer "):
            return token
        return f"Bearer {token}"

    if auth_type == "custom":
        value = (req.custom_auth or "").strip()
        if not value:
            raise HTTPException(400, "custom Authorization header value is required")
        return value

    raise HTTPException(400, "auth_type must be one of: none, basic, bearer, custom")


async def connector_json(method: str, path: str, *, json_body: Any = None):
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.request(method, f"{CONNECTOR_URL}{path}", json=json_body)
    try:
        data = res.json()
    except Exception:
        data = res.text
    if res.status_code >= 400:
        raise HTTPException(res.status_code, data)
    return data


async def connector_response(method: str, path: str, *, json_body: Any = None, headers=None, content=None):
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.request(method, f"{CONNECTOR_URL}{path}", json=json_body, headers=headers, content=content)
    return Response(content=res.content, status_code=res.status_code, media_type=res.headers.get("content-type"))


async def get_fc_entries():
    return await connector_json("GET", "/fc/debug/showAll")


async def get_authz_entries():
    return await connector_json("GET", "/authz/debug/show_all")


async def get_pkr_entries():
    return await connector_json("GET", "/pkr/debug/showAllKeys")


@app.get("/api/console/pkr/local-registered")
async def list_local_registered_pkr_entries():
    """Return only PKR entries that match this console's Local Keys."""
    db = SessionLocal()
    try:
        local_keys = {k.user_id: k.public_key.strip() for k in db.query(LocalKey).all()}
    finally:
        db.close()

    if not local_keys:
        return []

    pkr_items = await get_pkr_entries()
    return [
        item
        for item in pkr_items
        if item.get("user_id") in local_keys
        and (item.get("public_key") or "").strip() == local_keys[item.get("user_id")]
    ]


async def get_fc_entry(resource_id: str):
    data = await connector_json("GET", f"/fc/get?resource_id={resource_id}")
    if isinstance(data, list):
        if not data:
            raise HTTPException(404, "resource_id not found in Federated Catalog")
        return data[0]
    return data


@app.get("/")
async def index():
    return FileResponse("static/pkr.html")


@app.get("/{page}")
@app.get("/{page}.html")
async def page(page: str):
    if page not in {"pkr", "fc", "authz", "invoke"}:
        raise HTTPException(404, "not found")
    return FileResponse(f"static/{page}.html")


@app.get("/api/local-keys")
def list_local_keys():
    db = SessionLocal()
    try:
        return [key_to_dict(k) for k in db.query(LocalKey).order_by(LocalKey.user_id).all()]
    finally:
        db.close()


@app.post("/api/local-keys")
def create_local_key(req: UserReq):
    user_id = req.user_id.strip()
    if not user_id:
        raise HTTPException(400, "user_id is required")
    db = SessionLocal()
    try:
        if db.query(LocalKey).filter_by(user_id=user_id).first():
            raise HTTPException(409, "local key already exists")
        private_key, public_key = new_key_pair()
        key = LocalKey(user_id=user_id, private_key=private_key, public_key=public_key, registered_at=datetime.now(timezone.utc))
        db.add(key)
        db.commit()
        return key_to_dict(key)
    finally:
        db.close()


@app.post("/api/local-keys/debug/delete-all")
def debug_delete_all_local_keys():
    db = SessionLocal()
    try:
        deleted_count = db.query(LocalKey).delete()
        db.commit()
        return {"status": "deleted", "target": "local_keys", "deleted_count": deleted_count}
    finally:
        db.close()


@app.post("/api/console/pkr/register")
async def console_pkr_register(req: PkrUserReq):
    db = SessionLocal()
    try:
        key = get_local_key_or_400(db, req.user_id)
        payload = {"user_id": key.user_id, "public_key": key.public_key, "expire_time": iso_now_plus()}
        payload["signature"] = sign_payload(key.private_key, payload)
        return await connector_response("POST", "/pkr/add", json_body=payload)
    finally:
        db.close()


@app.post("/api/console/pkr/update")
async def console_pkr_update(req: PkrUserReq):
    db = SessionLocal()
    try:
        old_key = get_local_key_or_400(db, req.user_id)
        new_private_key, new_public_key = new_key_pair()
        payload = {"user_id": req.user_id, "new_public_key": new_public_key, "expire_time": iso_now_plus()}
        payload["signature"] = sign_payload(old_key.private_key, payload)
        res = await connector_json("POST", "/pkr/upd", json_body=payload)
        old_key.private_key = new_private_key
        old_key.public_key = new_public_key
        old_key.registered_at = datetime.now(timezone.utc)
        db.commit()
        return res
    finally:
        db.close()


@app.post("/api/console/pkr/delete")
async def console_pkr_delete(req: PkrUserReq):
    db = SessionLocal()
    deleted = {"federated_catalog": [], "authz": [], "public_key_registry": False, "local_key": False, "skipped_authz": []}
    try:
        key = get_local_key_or_400(db, req.user_id)
        fc_items = await get_fc_entries()
        owned_resources = [x for x in fc_items if x.get("user_id") == req.user_id]
        owned_resource_ids = [x["resource_id"] for x in owned_resources]
        authz_items = await get_authz_entries()
        target_authz = [x for x in authz_items if x.get("resource_id") in owned_resource_ids or x.get("access_grantee_id") == req.user_id]

        # 1. Federated Catalog
        for item in owned_resources:
            payload = {"resource_id": item["resource_id"], "expire_time": iso_now_plus()}
            payload["signature"] = sign_payload(key.private_key, payload)
            await connector_json("POST", "/fc/del", json_body=payload)
            deleted["federated_catalog"].append(item["resource_id"])

        # 2. AuthZ
        for item in target_authz:
            resource_id = item["resource_id"]
            grantee_id = item["access_grantee_id"]
            payload = {"resource_id": resource_id, "access_grantee_id": grantee_id, "expire_time": iso_now_plus()}
            try:
                if resource_id in owned_resource_ids:
                    signer_key = key
                else:
                    fc_entry = await get_fc_entry(resource_id)
                    signer_key = get_local_key_or_400(db, fc_entry["user_id"])
                payload["signature"] = sign_payload(signer_key.private_key, payload)
                await connector_json("POST", "/authz/del", json_body=payload)
                deleted["authz"].append(payload)
            except Exception as e:
                deleted["skipped_authz"].append({"resource_id": resource_id, "access_grantee_id": grantee_id, "reason": str(e)})

        # 3. Public Key Registry
        payload = {"user_id": req.user_id, "expire_time": iso_now_plus()}
        payload["signature"] = sign_payload(key.private_key, payload)
        await connector_json("POST", "/pkr/del", json_body=payload)
        deleted["public_key_registry"] = True

        # 4. Local Key
        db.delete(key)
        db.commit()
        deleted["local_key"] = True
        return {"status": "deleted", "user_id": req.user_id, "deleted": deleted}
    finally:
        db.close()


@app.post("/api/console/fc/add")
async def console_fc_add(req: FcEntryReq):
    db = SessionLocal()
    try:
        key = get_local_key_or_400(db, req.user_id)
        payload = req.model_dump()
        payload["expire_time"] = iso_now_plus()
        payload["signature"] = sign_payload(key.private_key, payload)
        return await connector_response("POST", "/fc/add", json_body=payload)
    finally:
        db.close()


@app.post("/api/console/fc/update")
async def console_fc_update(req: FcEntryReq):
    current = await get_fc_entry(req.resource_id)
    owner_id = current["user_id"]
    db = SessionLocal()
    try:
        owner_key = get_local_key_or_400(db, owner_id)
        signed_data = {
            "resource_id": req.resource_id,
            "user_id": owner_id,  # keep the existing owner; update only catalog fields
            "description": req.description,
            "endpoint": req.endpoint,
            "resource_path": req.resource_path,
            "expire_time": iso_now_plus(),
        }
        signature = sign_payload(owner_key.private_key, signed_data)
        payload = {
            **signed_data,
            "signature_old": signature,
            "signature_new": signature,
        }
        return await connector_response("POST", "/fc/upd", json_body=payload)
    finally:
        db.close()


@app.post("/api/console/fc/delete")
async def console_fc_delete(req: FcDeleteReq):
    current = await get_fc_entry(req.resource_id)
    db = SessionLocal()
    try:
        key = get_local_key_or_400(db, current["user_id"])
        payload = {"resource_id": req.resource_id, "expire_time": iso_now_plus()}
        payload["signature"] = sign_payload(key.private_key, payload)
        return await connector_response("POST", "/fc/del", json_body=payload)
    finally:
        db.close()


@app.post("/api/console/authz/add")
async def console_authz_add(req: AuthzReq):
    db = SessionLocal()
    try:
        key = get_local_key_or_400(db, req.user_id)
        payload = {
            "resource_id": req.resource_id,
            "access_grantee_id": req.access_grantee_id,
            "expired_at": req.expired_at,
            "expire_time": iso_now_plus(),
        }
        payload["signature"] = sign_payload(key.private_key, payload)
        return await connector_response("POST", "/authz/add", json_body=payload)
    finally:
        db.close()


@app.post("/api/console/authz/update")
async def console_authz_update(req: AuthzReq):
    db = SessionLocal()
    try:
        key = get_local_key_or_400(db, req.user_id)
        payload = {
            "resource_id": req.resource_id,
            "access_grantee_id": req.access_grantee_id,
            "expired_at": req.expired_at,
            "expire_time": iso_now_plus(),
        }
        payload["signature"] = sign_payload(key.private_key, payload)
        return await connector_response("POST", "/authz/upd", json_body=payload)
    finally:
        db.close()


@app.post("/api/console/authz/delete")
async def console_authz_delete(req: AuthzDeleteReq):
    db = SessionLocal()
    try:
        key = get_local_key_or_400(db, req.user_id)
        payload = {
            "resource_id": req.resource_id,
            "access_grantee_id": req.access_grantee_id,
            "expire_time": iso_now_plus(),
        }
        payload["signature"] = sign_payload(key.private_key, payload)
        return await connector_response("POST", "/authz/del", json_body=payload)
    finally:
        db.close()


@app.post("/api/console/authz/debug/delete-all")
async def console_authz_debug_delete_all():
    # Most current MVD AuthZ implementations expose this as POST.
    # Fall back to DELETE/GET so older PoC variants with debug endpoints still work.
    last_res = None
    async with httpx.AsyncClient(timeout=30.0) as client:
        for method in ("POST", "DELETE", "GET"):
            res = await client.request(method, f"{CONNECTOR_URL}/authz/debug/delete_all")
            last_res = res
            if res.status_code not in (404, 405):
                return Response(content=res.content, status_code=res.status_code, media_type=res.headers.get("content-type"))
    return Response(content=last_res.content if last_res else b"", status_code=last_res.status_code if last_res else 500)


@app.post("/api/console/invoke")
async def console_invoke(req: InvokeReq):
    db = SessionLocal()
    try:
        key = get_local_key_or_400(db, req.user_id)
        signed = {"resource_id": req.resource_id, "user_id": req.user_id, "expire_time": iso_now_plus()}
        signed["signature"] = sign_payload(key.private_key, signed)
        headers = {
            "X-Resource-Id": signed["resource_id"],
            "X-User-Id": signed["user_id"],
            "X-Expire-Time": signed["expire_time"],
            "X-Signature": signed["signature"],
        }
        headers.update(parse_extra_headers(req.extra_headers))

        authorization = build_authorization_header(req)
        if authorization:
            headers["Authorization"] = authorization

        path = "/invoke_resource"
        if req.query_params and req.query_params.strip():
            path += "?" + req.query_params.strip().lstrip("?")
        return await connector_response(req.method.upper(), path, headers=headers, content=req.body)
    finally:
        db.close()


async def proxy(method: str, path: str, request: Request):
    url = f"{CONNECTOR_URL}{path}"
    if request.url.query:
        url += f"?{request.url.query}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        res = await client.request(
            method,
            url,
            headers={k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")},
            content=await request.body(),
        )
    return Response(content=res.content, status_code=res.status_code, media_type=res.headers.get("content-type"))


@app.api_route("/api/pkr/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def api_pkr(path: str, request: Request):
    return await proxy(request.method, f"/pkr/{path}", request)


@app.api_route("/api/fc/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def api_fc(path: str, request: Request):
    return await proxy(request.method, f"/fc/{path}", request)


@app.api_route("/api/authz/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def api_authz(path: str, request: Request):
    return await proxy(request.method, f"/authz/{path}", request)
