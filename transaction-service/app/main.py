from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from pymongo import MongoClient
from dotenv import load_dotenv, find_dotenv
import jwt
import os
import uuid
import io
from datetime import datetime, timedelta
from typing import Optional

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

load_dotenv(find_dotenv())

app = FastAPI(title="Transaction Service", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client["sentinel_flow_demo"]
transactions_col = db["transactions"]
accounts_col = db["accounts"]

JWT_SECRET = os.getenv("JWT_SECRET", "sentinel-secret-key")
LARGE_TX_THRESHOLD = float(os.getenv("LARGE_TX_THRESHOLD", "500000"))


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

class TransferRequest(BaseModel):
    from_account_id: str
    to_account_id: str
    amount: float
    currency: str = "TWD"
    memo: str = ""


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_user_account_ids(username: str) -> list:
    return [
        a["account_id"]
        for a in accounts_col.find({"owner_username": username}, {"account_id": 1})
    ]


def build_statement_pdf(account: dict, txs: list, days: int) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15*mm, rightMargin=15*mm, topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("title", fontSize=16, fontName="Helvetica-Bold", textColor=colors.HexColor("#1a1a2e"), spaceAfter=6)
    sub_style = ParagraphStyle("sub", fontSize=9, fontName="Helvetica", textColor=colors.HexColor("#555555"), spaceAfter=4)

    elements = [
        Paragraph("SENTINEL FLOW BANK", title_style),
        Paragraph(f"Account Statement — {account['account_id']}", sub_style),
        Paragraph(f"Owner: {account['owner_username']}  |  Currency: {account['currency']}  |  Period: Last {days} days", sub_style),
        Paragraph(f"Current Balance: {account['balance']:,.2f} {account['currency']}  |  Status: {account['status'].upper()}", sub_style),
        Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sub_style),
        Spacer(1, 8*mm),
    ]

    col_widths = [25*mm, 25*mm, 35*mm, 35*mm, 30*mm, 22*mm, 22*mm]
    header = [["Date", "Type", "From Account", "To Account", "Memo", "Amount", "Status"]]
    rows = []
    for tx in txs:
        rows.append([
            tx.get("created_at", "")[:10],
            tx.get("type", "").replace("_", " ").title(),
            tx.get("from_account_id", "-"),
            tx.get("to_account_id", "-"),
            (tx.get("memo") or "")[:20],
            f"{tx.get('amount', 0):,.2f}",
            tx.get("status", ""),
        ])

    if not rows:
        rows = [["—", "No transactions in this period", "", "", "", "", ""]]

    table = Table(header + rows, colWidths=col_widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7fa")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(table)

    doc.build(elements)
    buf.seek(0)
    return buf.read()


# ── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/transactions/statement/{account_id}")
def get_statement(
    account_id: str,
    days: int = Query(default=30, ge=1, le=365),
    user: dict = Depends(get_current_user),
):
    account = accounts_col.find_one({"account_id": account_id}, {"_id": 0})
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    if account["owner_username"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    txs = list(
        transactions_col.find(
            {
                "$or": [{"from_account_id": account_id}, {"to_account_id": account_id}],
                "created_at": {"$gte": since},
            },
            {"_id": 0},
        ).sort("created_at", -1)
    )

    pdf_bytes = build_statement_pdf(account, txs, days)
    filename = f"statement_{account_id}_{days}d_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.post("/transactions/transfer", status_code=201)
def transfer(req: TransferRequest, user: dict = Depends(get_current_user)):
    if req.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    if req.from_account_id == req.to_account_id:
        raise HTTPException(status_code=400, detail="Cannot transfer to same account")

    from_acc = accounts_col.find_one({"account_id": req.from_account_id})
    if not from_acc:
        raise HTTPException(status_code=404, detail="Source account not found")
    if from_acc["owner_username"] != user["sub"] and user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    if from_acc["status"] != "active":
        raise HTTPException(status_code=400, detail=f"Source account is {from_acc['status']}")
    if from_acc["balance"] < req.amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    to_acc = accounts_col.find_one({"account_id": req.to_account_id})
    if not to_acc:
        raise HTTPException(status_code=404, detail="Destination account not found")
    if to_acc["status"] not in ("active", "pending_review"):
        raise HTTPException(status_code=400, detail=f"Destination account is {to_acc['status']}")

    tx_id = f"TX{uuid.uuid4().hex[:12].upper()}"
    now = datetime.utcnow().isoformat()

    accounts_col.update_one(
        {"account_id": req.from_account_id},
        {"$inc": {"balance": -req.amount}, "$set": {"updated_at": now}},
    )
    accounts_col.update_one(
        {"account_id": req.to_account_id},
        {"$inc": {"balance": req.amount}, "$set": {"updated_at": now}},
    )

    tx = {
        "transaction_id": tx_id,
        "type": "transfer",
        "from_account_id": req.from_account_id,
        "to_account_id": req.to_account_id,
        "amount": req.amount,
        "currency": req.currency,
        "memo": req.memo,
        "status": "completed",
        "initiated_by": user["sub"],
        "created_at": now,
        "flagged": req.amount >= LARGE_TX_THRESHOLD,
    }
    transactions_col.insert_one(tx)
    tx.pop("_id", None)
    return tx


@app.get("/transactions")
def list_transactions(
    account_id: Optional[str] = None,
    tx_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    user: dict = Depends(get_current_user),
):
    query: dict = {}
    if account_id:
        query["$or"] = [{"from_account_id": account_id}, {"to_account_id": account_id}]
    elif user.get("role") != "admin":
        ids = get_user_account_ids(user["sub"])
        query["$or"] = [{"from_account_id": {"$in": ids}}, {"to_account_id": {"$in": ids}}]

    if tx_type:
        query["type"] = tx_type
    if status:
        query["status"] = status

    txs = list(transactions_col.find(query, {"_id": 0}).sort("created_at", -1).limit(limit))
    return txs


@app.get("/transactions/{tx_id}")
def get_transaction(tx_id: str, user: dict = Depends(get_current_user)):
    tx = transactions_col.find_one({"transaction_id": tx_id}, {"_id": 0})
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if user.get("role") != "admin":
        user_ids = get_user_account_ids(user["sub"])
        if tx.get("from_account_id") not in user_ids and tx.get("to_account_id") not in user_ids:
            raise HTTPException(status_code=403, detail="Forbidden")
    return tx


@app.get("/transactions/stats/summary")
def transaction_stats(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    since_30d = (datetime.utcnow() - timedelta(days=30)).isoformat()
    total = transactions_col.count_documents({})
    recent = transactions_col.count_documents({"created_at": {"$gte": since_30d}})
    flagged = transactions_col.count_documents({"flagged": True})
    pipeline = [{"$group": {"_id": None, "total_amount": {"$sum": "$amount"}}}]
    agg = list(transactions_col.aggregate(pipeline))
    total_volume = agg[0]["total_amount"] if agg else 0
    return {
        "total_transactions": total,
        "recent_30d": recent,
        "flagged_count": flagged,
        "total_volume": total_volume,
    }


@app.get("/health")
def health():
    return {"status": "ok", "service": "transaction-service", "port": 8003}
