from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
import json, base64, hashlib, requests, time

from ecdsa import VerifyingKey

# =====================================================
# DB
# =====================================================
DATABASE_URL = "postgresql://user:password@db:5432/authz"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


class AuthzTable(Base):
    __tablename__ = "authz_entries"
    resource_id = Column(String, primary_key=True)
    access_grantee_id = Column(String, primary_key=True)
    valid_from = Column(DateTime, nullable=False)
    expired_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False)


# =====================================================
# FastAPI
# =====================================================
app = FastAPI(title="Authz (PoC)")

@app.on_event("startup")
def on_startup():
    time.sleep(3)
    Base.metadata.create_all(bind=engine)

# =====================================================
# Request models
# =====================================================
class AddAuthzReq(BaseModel):
    resource_id: str
    access_grantee_id: str
    valid_from: str # authz validity
    expired_at: str # authz validity
    expire_time: str # signature validity
    signature: str

class UpdAuthzReq(BaseModel):
    resource_id: str
    access_grantee_id: str
    valid_from: str # new expired_at
    expired_at: str # new expired_at
    expire_time: str
    signature: str

class DelAuthzReq(BaseModel):
    resource_id: str
    access_grantee_id: str
    expire_time: str
    signature: str


# =====================================================
# Signature helpers
# =====================================================
PKR_BASE_URL = "http://host.docker.internal:7450"
FC_BASE_URL = "http://host.docker.internal:7451"

def validate_expire(iso_time: str):
    t = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
    if t < datetime.now(timezone.utc):
        raise HTTPException(400, "expired")

def get_public_key(user_id: str) -> str:
    r = requests.get(f"{PKR_BASE_URL}/pkr/get/{user_id}")
    if r.status_code != 200:
        raise HTTPException(400, "public key not found")
    return r.json()["public_key"]

def get_owner_user_id_from_fc(resource_id: str) -> str:
    r = requests.get(f"{FC_BASE_URL}/fc/get", params={"resource_id": resource_id})
    if r.status_code != 200:
        raise HTTPException(400, "fc access failed")
    entries = r.json()
    if not entries:
        raise HTTPException(404, "resource_id not found")
    return entries[0]["user_id"]

def verify_signature(public_key_pem: str, data: dict, signature_b64: str) -> bool:
    try:
        vk = VerifyingKey.from_pem(public_key_pem.encode())
        msg = json.dumps(data, sort_keys=True).encode()
        sig = base64.b64decode(signature_b64)
        return vk.verify(sig, msg, hashfunc=hashlib.sha256)
    except Exception:
        return False

# =====================================================
# API
# =====================================================
@app.post("/authz/add")
def add_authz(req: AddAuthzReq):
    # 1. 署名の有効期限チェック
    validate_expire(req.expire_time)

    # 2. resource_id → owner user_id（FC）
    owner_user_id = get_owner_user_id_from_fc(req.resource_id)

    # 3. 署名対象データ
    data = {
        "resource_id": req.resource_id,
        "access_grantee_id": req.access_grantee_id,
        "valid_from": req.valid_from,
        "expired_at": req.expired_at,
        "expire_time": req.expire_time,
    }

    # 4. 公開鍵取得（PKR）
    public_key = get_public_key(owner_user_id)

    # 5. 署名検証
    if not verify_signature(public_key, data, req.signature):
        raise HTTPException(400, "invalid signature")

    # 6. DB 登録
    db = SessionLocal()
    if db.query(AuthzTable).filter_by(
        resource_id=req.resource_id,
        access_grantee_id=req.access_grantee_id,
    ).first():
        db.close()
        raise HTTPException(409, "already exists")

    db.add(
        AuthzTable(
            resource_id=req.resource_id,
            access_grantee_id=req.access_grantee_id,
            valid_from=datetime.fromisoformat(req.valid_from.replace("Z", "+00:00")),
            expired_at=datetime.fromisoformat(req.expired_at.replace("Z", "+00:00")),
            created_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    db.close()

    return {"status": "ok"}

@app.post("/authz/upd")
def upd_authz(req: UpdAuthzReq):
    validate_expire(req.expire_time)

    owner_user_id = get_owner_user_id_from_fc(req.resource_id)

    data = {
        "resource_id": req.resource_id,
        "access_grantee_id": req.access_grantee_id,
        "valid_from": req.valid_from,
        "expired_at": req.expired_at,
        "expire_time": req.expire_time,
    }

    public_key = get_public_key(owner_user_id)
    if not verify_signature(public_key, data, req.signature):
        raise HTTPException(400, "invalid signature")

    db = SessionLocal()
    authz = db.query(AuthzTable).filter_by(
        resource_id=req.resource_id,
        access_grantee_id=req.access_grantee_id,
    ).first()

    if not authz:
        db.close()
        raise HTTPException(404, "not found")

    authz.valid_from = datetime.fromisoformat(req.valid_from.replace("Z", "+00:00"))
    authz.expired_at = datetime.fromisoformat(req.expired_at.replace("Z", "+00:00"))
    db.commit()
    db.close()

    return {"status": "ok"}

@app.post("/authz/del")
def del_authz(req: DelAuthzReq):
    validate_expire(req.expire_time)

    owner_user_id = get_owner_user_id_from_fc(req.resource_id)

    data = {
        "resource_id": req.resource_id,
        "access_grantee_id": req.access_grantee_id,
        "expire_time": req.expire_time,
    }

    public_key = get_public_key(owner_user_id)
    if not verify_signature(public_key, data, req.signature):
        raise HTTPException(400, "invalid signature")

    db = SessionLocal()
    authz = db.query(AuthzTable).filter_by(
        resource_id=req.resource_id,
        access_grantee_id=req.access_grantee_id,
    ).first()

    if not authz:
        db.close()
        raise HTTPException(404, "not found")

    db.delete(authz)
    db.commit()
    db.close()

    return {"status": "ok"}

@app.get("/authz/get")
def get_authz(resource_id: str, access_grantee_id: str):
    db = SessionLocal()
    authz = db.query(AuthzTable).filter_by(
        resource_id=resource_id,
        access_grantee_id=access_grantee_id,
    ).first()
    db.close()

    if not authz:
        raise HTTPException(404, "not found")

    return {
        "resource_id": authz.resource_id,
        "access_grantee_id": authz.access_grantee_id,
        "valid_from": authz.valid_from.isoformat(),
        "expired_at": authz.expired_at.isoformat(),
        "created_at": authz.created_at.isoformat(),
    }


# =====================================================
# Debug APIs
# =====================================================
@app.get("/authz/debug/show_all")
def debug_show_all():
    db = SessionLocal()
    entries = db.query(AuthzTable).all()
    db.close()

    return [
        {
            "resource_id": e.resource_id,
            "access_grantee_id": e.access_grantee_id,
            "valid_from": e.valid_from.isoformat(),
            "expired_at": e.expired_at.isoformat(),
            "created_at": e.created_at.isoformat(),
        }
        for e in entries
    ]

@app.delete("/authz/debug/delete_all")
def debug_delete_all():
    db = SessionLocal()
    count = db.query(AuthzTable).delete()
    db.commit()
    db.close()
    return {"status": "ok", "deleted": count}
