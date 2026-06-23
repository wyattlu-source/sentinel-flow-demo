from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv
import jwt
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

load_dotenv(find_dotenv())

app = FastAPI(title="Risk Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client["sentinel_flow_demo"]
risk_events_col = db["risk_events"]
transactions_col = db["transactions"]
accounts_col = db["accounts"]
users_col = db["users"]

JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-secret-key")

AML_THRESHOLD_HIGH = float(os.getenv("AML_THRESHOLD_HIGH", "500000"))
AML_THRESHOLD_MED = float(os.getenv("AML_THRESHOLD_MED", "100000"))
FREQ_TRANSFER_LIMIT = int(os.getenv("FREQ_TRANSFER_LIMIT", "10"))

ADMIN_ROLES = {"admin", "risk_officer"}


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


# ── AML Rules Engine ──────────────────────────────────────────────────────────

def run_aml_rules(tx: dict) -> list[dict]:
    alerts = []
    amount = tx.get("amount", 0)
    from_acc_id = tx.get("from_account_id", "")

    if amount >= AML_THRESHOLD_HIGH:
        alerts.append({
            "rule": "LARGE_TRANSACTION",
            "severity": "critical",
            "description": f"Transaction of {amount:,.0f} exceeds high-risk AML threshold ({AML_THRESHOLD_HIGH:,.0f})",
        })
    elif amount >= AML_THRESHOLD_MED:
        alerts.append({
            "rule": "MEDIUM_TRANSACTION",
            "severity": "high",
            "description": f"Transaction of {amount:,.0f} requires enhanced due diligence",
        })

    if from_acc_id:
        from_acc = accounts_col.find_one({"account_id": from_acc_id})
        if from_acc and from_acc.get("status") == "frozen":
            alerts.append({
                "rule": "FROZEN_ACCOUNT_DEBIT",
                "severity": "critical",
                "description": "Transaction initiated from a frozen account — immediate review required",
            })

    initiator = tx.get("initiated_by")
    if initiator:
        since_1h = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        initiator_accounts = [
            a["account_id"]
            for a in accounts_col.find({"owner_username": initiator}, {"account_id": 1})
        ]
        recent_count = transactions_col.count_documents({
            "from_account_id": {"$in": initiator_accounts},
            "created_at": {"$gte": since_1h},
        })
        if recent_count >= FREQ_TRANSFER_LIMIT:
            alerts.append({
                "rule": "FREQUENT_TRANSFERS",
                "severity": "high",
                "description": f"User {initiator} made {recent_count} transfers in the last hour (limit: {FREQ_TRANSFER_LIMIT})",
            })

    return alerts


# ── Credit Score Engine ───────────────────────────────────────────────────────

def compute_credit_score(username: str) -> dict:
    user_accounts = list(accounts_col.find({"owner_username": username}, {"_id": 0}))
    if not user_accounts:
        return {"score": 500, "grade": "C", "rating": "Fair", "factors": ["No account history"]}

    account_ids = [a["account_id"] for a in user_accounts]
    total_balance = sum(a.get("balance", 0) for a in user_accounts)
    active_count = sum(1 for a in user_accounts if a.get("status") == "active")
    frozen_count = sum(1 for a in user_accounts if a.get("status") == "frozen")

    since_90d = (datetime.utcnow() - timedelta(days=90)).isoformat()
    tx_count = transactions_col.count_documents({
        "$or": [{"from_account_id": {"$in": account_ids}}, {"to_account_id": {"$in": account_ids}}],
        "created_at": {"$gte": since_90d},
    })
    failed_tx = transactions_col.count_documents({
        "from_account_id": {"$in": account_ids},
        "status": "failed",
        "created_at": {"$gte": since_90d},
    })
    open_events = risk_events_col.count_documents({"username": username, "status": "open"})

    score = 650
    factors = []

    if total_balance >= 5_000_000:
        score += 80
        factors.append("Excellent account balance (≥5M)")
    elif total_balance >= 1_000_000:
        score += 50
        factors.append("High account balance (≥1M)")
    elif total_balance >= 100_000:
        score += 20
        factors.append("Adequate account balance")
    elif total_balance < 10_000:
        score -= 40
        factors.append("Low account balance")

    if tx_count >= 30:
        score += 30
        factors.append("Active transaction history")
    elif tx_count >= 10:
        score += 15
        factors.append("Moderate transaction history")

    if failed_tx > 5:
        score -= 40
        factors.append(f"High failed transaction count ({failed_tx})")
    elif failed_tx > 2:
        score -= 15
        factors.append(f"Some failed transactions ({failed_tx})")

    if frozen_count > 0:
        score -= 100
        factors.append(f"{frozen_count} frozen account(s)")

    if open_events > 0:
        score -= open_events * 25
        factors.append(f"{open_events} open risk event(s)")

    if active_count >= 2:
        score += 10
        factors.append("Multiple active accounts")

    score = max(300, min(850, score))

    if score >= 750:
        grade, rating = "A", "Excellent"
    elif score >= 680:
        grade, rating = "B", "Good"
    elif score >= 580:
        grade, rating = "C", "Fair"
    elif score >= 480:
        grade, rating = "D", "Poor"
    else:
        grade, rating = "F", "Very Poor"

    return {"score": score, "grade": grade, "rating": rating, "factors": factors}


# ── Models ────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    transaction_id: str


class ReviewRequest(BaseModel):
    action: str  # "resolved" | "investigating" | "false_positive"
    notes: str = ""


class CreateEventRequest(BaseModel):
    username: str
    event_type: str
    severity: str
    description: str


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/risk/events")
def list_risk_events(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(get_current_user),
):
    query: dict = {}
    if user.get("role") not in ADMIN_ROLES:
        query["username"] = user["sub"]
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity

    events = list(risk_events_col.find(query, {"_id": 0}).sort("created_at", -1).limit(limit))
    return events


@app.get("/risk/score/{username}")
def get_credit_score(username: str, user: dict = Depends(get_current_user)):
    if username != user["sub"] and user.get("role") not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Forbidden")
    result = compute_credit_score(username)
    return {
        "username": username,
        "computed_at": datetime.utcnow().isoformat(),
        **result,
    }


@app.post("/risk/analyze")
def analyze_transaction(req: AnalyzeRequest, user: dict = Depends(get_current_user)):
    tx = transactions_col.find_one({"transaction_id": req.transaction_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    alerts = run_aml_rules(tx)
    created_events = []
    for alert in alerts:
        event_id = f"RE{uuid.uuid4().hex[:10].upper()}"
        event = {
            "event_id": event_id,
            "event_type": alert["rule"],
            "severity": alert["severity"],
            "description": alert["description"],
            "transaction_id": req.transaction_id,
            "username": tx.get("initiated_by"),
            "status": "open",
            "created_at": datetime.utcnow().isoformat(),
        }
        risk_events_col.insert_one(event)
        event.pop("_id", None)
        created_events.append(event)

    return {
        "transaction_id": req.transaction_id,
        "aml_passed": len(alerts) == 0,
        "alerts_count": len(alerts),
        "events_created": created_events,
    }


@app.get("/risk/anomalies")
def get_anomalies(user: dict = Depends(get_current_user)):
    if user.get("role") not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Admin/Risk Officer only")

    since_7d = (datetime.utcnow() - timedelta(days=7)).isoformat()
    high_value = list(
        transactions_col.find(
            {"amount": {"$gte": AML_THRESHOLD_MED}, "created_at": {"$gte": since_7d}},
            {"_id": 0},
        ).sort("amount", -1).limit(20)
    )
    critical_events = list(
        risk_events_col.find(
            {"severity": "critical", "status": "open"},
            {"_id": 0},
        ).sort("created_at", -1).limit(10)
    )
    return {
        "high_value_transactions": high_value,
        "critical_open_events": critical_events,
        "generated_at": datetime.utcnow().isoformat(),
    }


@app.put("/risk/events/{event_id}/review")
def review_event(
    event_id: str,
    req: ReviewRequest,
    user: dict = Depends(get_current_user),
):
    if user.get("role") not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Admin/Risk Officer only")

    valid_actions = {"resolved", "investigating", "false_positive", "escalated"}
    if req.action not in valid_actions:
        raise HTTPException(status_code=400, detail=f"Invalid action. Use: {valid_actions}")

    result = risk_events_col.update_one(
        {"event_id": event_id},
        {
            "$set": {
                "status": req.action,
                "review_notes": req.notes,
                "reviewed_by": user["sub"],
                "reviewed_at": datetime.utcnow().isoformat(),
            }
        },
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Risk event not found")
    return {"message": "Risk event updated", "event_id": event_id, "new_status": req.action}


@app.post("/risk/events", status_code=201)
def create_event(req: CreateEventRequest, user: dict = Depends(get_current_user)):
    if user.get("role") not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Admin/Risk Officer only")

    valid_severities = {"low", "medium", "high", "critical"}
    if req.severity not in valid_severities:
        raise HTTPException(status_code=400, detail=f"Invalid severity. Use: {valid_severities}")

    event_id = f"RE{uuid.uuid4().hex[:10].upper()}"
    event = {
        "event_id": event_id,
        "event_type": req.event_type,
        "severity": req.severity,
        "description": req.description,
        "username": req.username,
        "status": "open",
        "created_by": user["sub"],
        "created_at": datetime.utcnow().isoformat(),
    }
    risk_events_col.insert_one(event)
    event.pop("_id", None)
    return event


@app.get("/risk/dashboard")
def risk_dashboard(user: dict = Depends(get_current_user)):
    if user.get("role") not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Admin/Risk Officer only")

    by_severity = {}
    for sev in ("low", "medium", "high", "critical"):
        by_severity[sev] = risk_events_col.count_documents({"severity": sev, "status": "open"})

    total_open = risk_events_col.count_documents({"status": "open"})
    total_resolved = risk_events_col.count_documents({"status": "resolved"})
    since_24h = (datetime.utcnow() - timedelta(hours=24)).isoformat()
    new_24h = risk_events_col.count_documents({"created_at": {"$gte": since_24h}})

    return {
        "open_by_severity": by_severity,
        "total_open": total_open,
        "total_resolved": total_resolved,
        "new_last_24h": new_24h,
        "as_of": datetime.utcnow().isoformat(),
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "risk-service", "port": 8004}
