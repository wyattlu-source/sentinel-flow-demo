from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from bson import ObjectId
from dotenv import load_dotenv, find_dotenv
import jwt
import os
from datetime import datetime
from typing import Optional

load_dotenv(find_dotenv())

app = FastAPI(title="Notification Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client["sentinel_flow_demo"]
notifications_col = db["notifications"]

JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-secret-key")

VALID_TYPES = {"transaction_alert", "risk_alert", "system_notice", "account_alert", "login_alert"}
VALID_CHANNELS = {"system", "email", "sms", "push"}


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(authorization: str = Header(...)) -> dict:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    return decode_token(authorization[7:])


def serialize(n: dict) -> dict:
    n["id"] = str(n.pop("_id"))
    return n


# ── Models ────────────────────────────────────────────────────────────────────

class SendRequest(BaseModel):
    username: str
    type: str
    title: str
    message: str
    channel: str = "system"
    metadata: Optional[dict] = None


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/notifications/unread-count")
def unread_count(user: dict = Depends(get_current_user)):
    query = {"username": user["sub"], "is_read": False} if user.get("role") != "admin" else {"is_read": False}
    count = notifications_col.count_documents(query)
    return {"count": count, "username": user["sub"]}


@app.put("/notifications/read-all")
def mark_all_read(user: dict = Depends(get_current_user)):
    query = {"username": user["sub"]} if user.get("role") != "admin" else {}
    result = notifications_col.update_many(
        {**query, "is_read": False},
        {"$set": {"is_read": True, "read_at": datetime.utcnow().isoformat()}},
    )
    return {"message": "All notifications marked as read", "updated": result.modified_count}


@app.get("/notifications")
def list_notifications(
    unread_only: bool = False,
    notif_type: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(get_current_user),
):
    query: dict = {} if user.get("role") == "admin" else {"username": user["sub"]}
    if unread_only:
        query["is_read"] = False
    if notif_type:
        query["type"] = notif_type

    notifs = list(notifications_col.find(query).sort("created_at", -1).limit(limit))
    return [serialize(n) for n in notifs]


@app.put("/notifications/{notif_id}/read")
def mark_read(notif_id: str, user: dict = Depends(get_current_user)):
    try:
        oid = ObjectId(notif_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid notification ID")

    query: dict = {"_id": oid}
    if user.get("role") != "admin":
        query["username"] = user["sub"]

    result = notifications_col.update_one(
        query,
        {"$set": {"is_read": True, "read_at": datetime.utcnow().isoformat()}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"message": "Marked as read", "id": notif_id}


@app.post("/notifications/send", status_code=201)
def send_notification(req: SendRequest, user: dict = Depends(get_current_user)):
    if user.get("role") not in ("admin", "system"):
        raise HTTPException(status_code=403, detail="Admin only")
    if req.type not in VALID_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid type. Use: {VALID_TYPES}")
    if req.channel not in VALID_CHANNELS:
        raise HTTPException(status_code=400, detail=f"Invalid channel. Use: {VALID_CHANNELS}")

    notif = {
        "username": req.username,
        "type": req.type,
        "title": req.title,
        "message": req.message,
        "channel": req.channel,
        "metadata": req.metadata or {},
        "is_read": False,
        "created_at": datetime.utcnow().isoformat(),
        "sent_by": user["sub"],
    }
    result = notifications_col.insert_one(notif)
    notif["id"] = str(result.inserted_id)
    notif.pop("_id", None)
    return notif


@app.delete("/notifications/{notif_id}")
def delete_notification(notif_id: str, user: dict = Depends(get_current_user)):
    try:
        oid = ObjectId(notif_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid notification ID")

    query: dict = {"_id": oid}
    if user.get("role") != "admin":
        query["username"] = user["sub"]

    result = notifications_col.delete_one(query)
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"message": "Notification deleted", "id": notif_id}


@app.get("/health")
def health():
    return {"status": "ok", "service": "notification-service", "port": 8005}
