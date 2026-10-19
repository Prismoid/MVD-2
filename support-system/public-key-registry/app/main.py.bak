from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
import json, base64, hashlib, time

from ecdsa import VerifyingKey

# =====================================================
# DB
# =====================================================
DATABASE_URL = "postgresql://user:password@db:5432/public_key_registry"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class RegisteredPublicKey(Base):
    __tablename__ = "registered_public_keys"
    user_id = Column(String, primary_key=True)
    public_key = Column(String, nullable=False)
    registered_at = Column(DateTime, nullable=False)

# =====================================================
# FastAPI
# =====================================================
app = FastAPI(title="Public Key Registry (PoC)")

@app.on_event("startup")
def on_startup():
    time.sleep(2)
    Base.metadata.create_all(bind=engine)

# =====================================================
# Request models
# =====================================================
class AddKeyReq(BaseModel):
    user_id: str
    public_key: str
    expire_time: str
    signature: str

class UpdKeyReq(BaseModel):
    user_id: str
    new_public_key: str
    expire_time: str
    signature: str

class DelKeyReq(BaseModel):
    user_id: str
    expire_time: str
    signature: str

# =====================================================
# Signature helpers
# =====================================================
def verify_signature(public_key_pem: str, data: dict, signature_b64: str) -> bool:
    try:
        vk = VerifyingKey.from_pem(public_key_pem.encode())
        msg = json.dumps(data, sort_keys=True).encode()
        sig = base64.b64decode(signature_b64)
        return vk.verify(sig, msg, hashfunc=hashlib.sha256)
    except Exception:
        return False

def validate_expire(iso_time: str):
    t = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
    if t < datetime.now(timezone.utc):
        raise HTTPException(400, "expired")

# =====================================================
# API
# =====================================================
@app.post("/pkr/add")
def add_key(req: AddKeyReq):
    data = {
        "user_id": req.user_id,
        "public_key": req.public_key,
        "expire_time": req.expire_time,
    }

    validate_expire(req.expire_time)

    if not verify_signature(req.public_key, data, req.signature):
        raise HTTPException(400, "invalid signature")

    db = SessionLocal()
    if db.query(RegisteredPublicKey).filter_by(user_id=req.user_id).first():
        db.close()
        raise HTTPException(409, "already registered")

    db.add(
        RegisteredPublicKey(
            user_id=req.user_id,
            public_key=req.public_key,
            registered_at=datetime.now(timezone.utc),
        )
    )
    db.commit()
    db.close()

    return {"status": "ok", "user_id": req.user_id}

@app.post("/pkr/upd")
def upd_key(req: UpdKeyReq):
    data = {
        "user_id": req.user_id,
        "new_public_key": req.new_public_key,
        "expire_time": req.expire_time,
    }

    # expire チェック
    validate_expire(req.expire_time)

    db = SessionLocal()
    key = db.query(RegisteredPublicKey).filter_by(user_id=req.user_id).first()
    if not key:
        db.close()
        raise HTTPException(404, "not found")

    # 旧公開鍵で署名検証
    if not verify_signature(key.public_key, data, req.signature):
        db.close()
        raise HTTPException(400, "invalid signature")

    # 更新
    key.public_key = req.new_public_key
    key.registered_at = datetime.now(timezone.utc)

    db.commit()
    db.close()

    return {
        "status": "updated",
        "user_id": req.user_id,
    }

@app.post("/pkr/del")
def del_key(req: DelKeyReq):
    data = {
        "user_id": req.user_id,
        "expire_time": req.expire_time,
    }

    validate_expire(req.expire_time)

    db = SessionLocal()
    key = db.query(RegisteredPublicKey).filter_by(user_id=req.user_id).first()
    if not key:
        db.close()
        raise HTTPException(404, "not found")

    if not verify_signature(key.public_key, data, req.signature):
        db.close()
        raise HTTPException(400, "invalid signature")

    db.delete(key)
    db.commit()
    db.close()

    return {"status": "deleted", "user_id": req.user_id}

@app.get("/pkr/get/{user_id}")
def get_key(user_id: str):
    db = SessionLocal()
    key = db.query(RegisteredPublicKey).filter_by(user_id=user_id).first()
    db.close()

    if not key:
        raise HTTPException(404, "not found")

    return {
        "user_id": key.user_id,
        "public_key": key.public_key,
        "registered_at": key.registered_at.isoformat(),
    }

# =====================================================
# Debug APIs
# =====================================================
@app.get("/pkr/debug/showAllKeys")
def debug_show_all():
    db = SessionLocal()
    keys = db.query(RegisteredPublicKey).all()
    db.close()

    return [
        {
            "user_id": k.user_id,
            "public_key": k.public_key,
            "registered_at": k.registered_at.isoformat(),
        }
        for k in keys
    ]

@app.delete("/pkr/debug/delAllKeys")
def debug_delete_all():
    db = SessionLocal()
    count = db.query(RegisteredPublicKey).delete()
    db.commit()
    db.close()
    return {"deleted": count}
