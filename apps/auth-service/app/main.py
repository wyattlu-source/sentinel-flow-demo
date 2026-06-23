from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv
import jwt
import bcrypt
import os
from datetime import datetime, timedelta
from typing import Optional

load_dotenv(find_dotenv())

app = FastAPI(title="Auth Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client["sentinel_flow_demo"]
users_col = db["users"]

JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-secret-key")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(payload: dict, hours: float = 8.0) -> str:
    data = {
        **payload,
        "exp": datetime.utcnow() + timedelta(hours=hours),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(data, JWT_SECRET, algorithm="HS256")
    return token.decode("utf-8") if isinstance(token, bytes) else token


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


# ── Models ──────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class OTPVerifyRequest(BaseModel):
    username: str
    otp_code: str
    temp_token: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.post("/auth/login")
def login(req: LoginRequest):
    user = users_col.find_one({"username": req.username})
    if not user or not verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("status") == "locked":
        raise HTTPException(status_code=403, detail="Account locked due to policy violation")

    users_col.update_one(
        {"username": req.username},
        {"$set": {"last_login": datetime.utcnow().isoformat()}, "$inc": {"login_count": 1}},
    )

    if user.get("otp_enabled"):
        temp = create_token({"sub": user["username"], "type": "otp_pending"}, hours=0.25)
        return {
            "otp_required": True,
            "temp_token": temp,
            "message": "OTP verification required. Check your authenticator app.",
        }

    access = create_token(
        {"sub": user["username"], "role": user.get("role", "user"), "type": "access"}
    )
    refresh = create_token({"sub": user["username"], "type": "refresh"}, hours=168)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "name": user.get("name"),
            "role": user.get("role", "user"),
            "email": user.get("email"),
            "tier": user.get("tier", "standard"),
        },
    }


@app.post("/auth/otp/verify")
def verify_otp(req: OTPVerifyRequest):
    payload = decode_token(req.temp_token)
    if payload.get("type") != "otp_pending":
        raise HTTPException(status_code=401, detail="Invalid temp token type")
    if payload.get("sub") != req.username:
        raise HTTPException(status_code=401, detail="Username mismatch")

    user = users_col.find_one({"username": req.username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("otp_code") != req.otp_code:
        users_col.update_one({"username": req.username}, {"$inc": {"otp_fail_count": 1}})
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    users_col.update_one({"username": req.username}, {"$set": {"otp_fail_count": 0}})

    access = create_token(
        {"sub": user["username"], "role": user.get("role", "user"), "type": "access"}
    )
    refresh = create_token({"sub": user["username"], "type": "refresh"}, hours=168)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "user": {
            "username": user["username"],
            "name": user.get("name"),
            "role": user.get("role", "user"),
            "email": user.get("email"),
            "tier": user.get("tier", "standard"),
        },
    }


@app.post("/auth/token/refresh")
def refresh_token(req: RefreshRequest):
    payload = decode_token(req.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    user = users_col.find_one({"username": payload["sub"]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.get("status") == "locked":
        raise HTTPException(status_code=403, detail="Account locked")

    access = create_token(
        {"sub": user["username"], "role": user.get("role", "user"), "type": "access"}
    )
    return {"access_token": access, "token_type": "bearer"}


@app.get("/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    user = users_col.find_one({"username": current_user["sub"]}, {"password_hash": 0, "_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.put("/auth/me/password")
def change_password(req: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    user = users_col.find_one({"username": current_user["sub"]})
    if not user or not verify_password(req.old_password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Old password incorrect")
    users_col.update_one(
        {"username": current_user["sub"]},
        {"$set": {"password_hash": hash_password(req.new_password), "pwd_changed_at": datetime.utcnow().isoformat()}},
    )
    return {"message": "Password updated successfully"}


@app.get("/auth/users")
def list_users(current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return list(users_col.find({}, {"password_hash": 0, "_id": 0}))


@app.put("/auth/users/{username}/lock")
def lock_user(username: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    result = users_col.update_one({"username": username}, {"$set": {"status": "locked"}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"User {username} locked"}


@app.put("/auth/users/{username}/unlock")
def unlock_user(username: str, current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    result = users_col.update_one({"username": username}, {"$set": {"status": "active"}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"User {username} unlocked"}


@app.get("/health")
def health():
    return {"status": "ok", "service": "auth-service", "port": 8001}
