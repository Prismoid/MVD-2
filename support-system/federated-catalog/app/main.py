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
DATABASE_URL = "postgresql://user:password@db:5432/federated_catalog"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class CatalogEntry(Base):
    __tablename__ = "catalog_entries"

    resource_id = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    description = Column(String, nullable=False)
    endpoint = Column(String, nullable=False)
    resource_path = Column(String, nullable=False)
    registered_at = Column(DateTime, nullable=False)

# =====================================================
# FastAPI
# =====================================================
app = FastAPI(title="Federated Catalog (PoC)")

@app.on_event("startup")
def on_startup():
    time.sleep(3)
    Base.metadata.create_all(bind=engine)

# =====================================================
# Request models
# =====================================================
class AddCatReq(BaseModel):
    resource_id: str
    user_id: str
    description: str
    endpoint: str
    resource_path: str
    expire_time: str
    signature: str

class UpdCatReq(BaseModel):
    resource_id: str
    user_id: str # new owner
    description: str
    endpoint: str
    resource_path: str
    expire_time: str
    signature_old: str
    signature_new: str

class DelCatReq(BaseModel):
    resource_id: str
    expire_time: str
    signature: str

# =====================================================
# Signature helpers
# =====================================================
PKR_BASE_URL = "http://host.docker.internal:7450"

def validate_expire(iso_time: str):
    t = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
    if t < datetime.now(timezone.utc):
        raise HTTPException(400, "expired")

def get_public_key(user_id: str) -> str:
    r = requests.get(f"{PKR_BASE_URL}/pkr/get/{user_id}")
    if r.status_code != 200:
        raise HTTPException(400, "public key not found")
    return r.json()["public_key"]

def verify_signature(public_key_pem: str, data: dict, signature_b64: str) -> bool:
    try:
        vk = VerifyingKey.from_pem(public_key_pem.encode()); msg = json.dumps(data, sort_keys=True).encode()
        sig = base64.b64decode(signature_b64)
        return vk.verify(sig, msg, hashfunc=hashlib.sha256)
    except Exception:
        return False

# =====================================================
# API
# =====================================================
@app.post("/fc/add")
def add_cat(req: AddCatReq):
    validate_expire(req.expire_time)

    data = {
        "resource_id": req.resource_id,
        "user_id": req.user_id,
        "description": req.description,
        "endpoint": req.endpoint,
        "resource_path": req.resource_path,
        "expire_time": req.expire_time,
    }

    public_key = get_public_key(req.user_id)
    if not verify_signature(public_key, data, req.signature):
        raise HTTPException(400, "invalid signature")

    db = SessionLocal()
    if db.query(CatalogEntry).filter_by(resource_id=req.resource_id).first():
        db.close()
        raise HTTPException(409, "already exists")

    db.add(
        CatalogEntry(
            resource_id=req.resource_id,
            user_id=req.user_id,
            description=req.description,
            endpoint=req.endpoint,
            resource_path=req.resource_path,
            registered_at=datetime.now(timezone.utc),
        )
    )
    db.commit(); db.close()

    return {"status": "ok", "resource_id": req.resource_id}

@app.post("/fc/upd")
def upd_cat(req: UpdCatReq):
    validate_expire(req.expire_time)

    db = SessionLocal()
    entry = db.query(CatalogEntry).filter_by(resource_id=req.resource_id).first()
    if not entry:
        db.close()
        raise HTTPException(404, "not found")

    current_owner = entry.user_id
    new_owner = req.user_id

    # 署名対象データ（両者で完全一致させる）
    data = {
        "resource_id": req.resource_id,
        "user_id": req.user_id,          # new owner
        "description": req.description,
        "endpoint": req.endpoint,
        "resource_path": req.resource_path,
        "expire_time": req.expire_time,
    }

    # =====================================================
    # 旧 owner の署名検証
    # =====================================================
    old_owner_pub = get_public_key(current_owner)
    if not verify_signature(old_owner_pub, data, req.signature_old):
        db.close()
        raise HTTPException(400, "invalid signature (old owner)")

    # =====================================================
    # 新 owner の署名検証
    # =====================================================
    new_owner_pub = get_public_key(new_owner)
    if not verify_signature(new_owner_pub, data, req.signature_new):
        db.close()
        raise HTTPException(400, "invalid signature (new owner)")

    # =====================================================
    # 更新（owner 移譲）
    # =====================================================
    entry.user_id = new_owner
    entry.description = req.description
    entry.endpoint = req.endpoint
    entry.resource_path = req.resource_path
    entry.registered_at = datetime.now(timezone.utc)

    db.commit(); db.close()

    return {
        "status": "updated",
        "resource_id": req.resource_id,
        "old_user_id": current_owner,
        "new_user_id": new_owner,
    }


@app.post("/fc/del")
def del_cat(req: DelCatReq):
    validate_expire(req.expire_time)

    db = SessionLocal()
    entry = db.query(CatalogEntry).filter_by(resource_id=req.resource_id).first()
    if not entry:
        db.close()
        raise HTTPException(404, "not found")

    current_owner = entry.user_id

    data = {
        "resource_id": req.resource_id,
        "expire_time": req.expire_time,
    }

    public_key = get_public_key(current_owner)
    if not verify_signature(public_key, data, req.signature):
        db.close()
        raise HTTPException(400, "invalid signature")

    db.delete(entry); db.commit(); db.close()

    return {"status": "deleted", "resource_id": req.resource_id}

@app.get("/fc/get")
def get_cat(keyword: str = Query(None), resource_id: str = Query(None), user_id: str = Query(None)):
    db = SessionLocal()
    q = db.query(CatalogEntry)

    if keyword:
        q = q.filter(CatalogEntry.description.contains(keyword))
    if resource_id:
        q = q.filter(CatalogEntry.resource_id == resource_id)
    if user_id:
        q = q.filter(CatalogEntry.user_id == user_id)

    entries = q.all()
    db.close()
    return [
        {
            "resource_id": e.resource_id,
            "user_id": e.user_id,
            "description": e.description,
            "endpoint": e.endpoint,
            "resource_path": e.resource_path,
            "registered_at": e.registered_at.isoformat(),
        }
        for e in entries
    ]

# =====================================================
# Debug APIs
# =====================================================
@app.get("/fc/debug/showAll")
def debug_show_all():
    db = SessionLocal()
    entries = db.query(CatalogEntry).all()
    db.close()

    return [
        {
            "resource_id": e.resource_id,
            "user_id": e.user_id,
            "description": e.description,
            "endpoint": e.endpoint,
            "resource_path": e.resource_path,
            "registered_at": e.registered_at.isoformat(),
        }
        for e in entries
    ]

@app.delete("/fc/debug/delAll")
def debug_delete_all():
    db = SessionLocal()
    count = db.query(CatalogEntry).delete()
    db.commit()
    db.close()
    return {"deleted": count}
