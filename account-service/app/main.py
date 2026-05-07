from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv
import jwt
import os
import uuid
from datetime import datetime
from typing import Optional

load_dotenv(find_dotenv())

app = FastAPI(title="Account Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client["sentinel_flow_demo"]
accounts_col = db["accounts"]

JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-secret-key")

CURRENCY_PREFIX = {"TWD": "T", "USD": "U", "HKD": "H"}
SUPPORTED_CURRENCIES = {"TWD", "USD", "HKD"}
ACCOUNT_TYPES = {"savings", "checking", "investment"}


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


# ── Models ───────────────────────────────────────────────────────────────────

class OpenAccountRequest(BaseModel):
    currency: str = "TWD"
    account_type: str = "savings"
    initial_deposit: float = 0.0


class UpdateAccountRequest(BaseModel):
    nickname: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def gen_account_id(currency: str) -> str:
    prefix = CURRENCY_PREFIX.get(currency, "X")
    return f"{prefix}{uuid.uuid4().hex[:10].upper()}"


def assert_owner_or_admin(account: dict, user: dict):
    if account["owner_username"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden")


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/accounts")
def list_accounts(
    currency: Optional[str] = None,
    status: Optional[str] = None,
    user: dict = Depends(get_current_user),
):
    query = {} if user.get("role") == "admin" else {"owner_username": user["sub"]}
    if currency:
        query["currency"] = currency.upper()
    if status:
        query["status"] = status
    accounts = list(accounts_col.find(query, {"_id": 0}).sort("created_at", -1))
    return accounts


@app.get("/accounts/summary")
def account_summary(user: dict = Depends(get_current_user)):
    query = {} if user.get("role") == "admin" else {"owner_username": user["sub"]}
    accounts = list(accounts_col.find(query, {"_id": 0}))
    by_currency: dict = {}
    by_status: dict = {}
    for acc in accounts:
        cur = acc["currency"]
        by_currency[cur] = by_currency.get(cur, 0.0) + acc.get("balance", 0.0)
        st = acc["status"]
        by_status[st] = by_status.get(st, 0) + 1
    return {
        "total_accounts": len(accounts),
        "balance_by_currency": by_currency,
        "count_by_status": by_status,
        "accounts": accounts,
    }


@app.get("/accounts/{account_id}")
def get_account(account_id: str, user: dict = Depends(get_current_user)):
    account = accounts_col.find_one({"account_id": account_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    assert_owner_or_admin(account, user)
    return account


@app.get("/accounts/{account_id}/balance")
def get_balance(account_id: str, user: dict = Depends(get_current_user)):
    account = accounts_col.find_one({"account_id": account_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    assert_owner_or_admin(account, user)
    return {
        "account_id": account_id,
        "balance": account["balance"],
        "currency": account["currency"],
        "status": account["status"],
        "as_of": datetime.utcnow().isoformat(),
    }


@app.post("/accounts/open", status_code=201)
def open_account(req: OpenAccountRequest, user: dict = Depends(get_current_user)):
    if req.currency.upper() not in SUPPORTED_CURRENCIES:
        raise HTTPException(status_code=400, detail=f"Unsupported currency. Use: {SUPPORTED_CURRENCIES}")
    if req.account_type not in ACCOUNT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid account type. Use: {ACCOUNT_TYPES}")
    if req.initial_deposit < 0:
        raise HTTPException(status_code=400, detail="Initial deposit cannot be negative")

    account_id = gen_account_id(req.currency.upper())
    now = datetime.utcnow().isoformat()
    account = {
        "account_id": account_id,
        "owner_username": user["sub"],
        "currency": req.currency.upper(),
        "account_type": req.account_type,
        "balance": req.initial_deposit,
        "status": "pending_review",
        "nickname": None,
        "created_at": now,
        "updated_at": now,
    }
    accounts_col.insert_one(account)
    account.pop("_id", None)
    return account


@app.put("/accounts/{account_id}")
def update_account(
    account_id: str,
    req: UpdateAccountRequest,
    user: dict = Depends(get_current_user),
):
    account = accounts_col.find_one({"account_id": account_id})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    assert_owner_or_admin(account, user)
    updates = {"updated_at": datetime.utcnow().isoformat()}
    if req.nickname is not None:
        updates["nickname"] = req.nickname
    accounts_col.update_one({"account_id": account_id}, {"$set": updates})
    return {"message": "Account updated", "account_id": account_id}


@app.put("/accounts/{account_id}/freeze")
def freeze_account(account_id: str, user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    result = accounts_col.update_one(
        {"account_id": account_id},
        {"$set": {"status": "frozen", "updated_at": datetime.utcnow().isoformat()}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"message": "Account frozen", "account_id": account_id}


@app.put("/accounts/{account_id}/activate")
def activate_account(account_id: str, user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    result = accounts_col.update_one(
        {"account_id": account_id},
        {"$set": {"status": "active", "updated_at": datetime.utcnow().isoformat()}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"message": "Account activated", "account_id": account_id}


@app.get("/health")
def health():
    return {"status": "ok", "service": "account-service", "port": 8002}
