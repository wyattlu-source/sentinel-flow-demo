"""
Seed script for sentinel_flow_demo database.
Usage: python seed_data.py
Requires: .env file with MONGODB_URI set.
"""
import hashlib
import os
import random
import uuid
from datetime import datetime, timedelta

from dotenv import load_dotenv, find_dotenv
from pymongo import MongoClient

load_dotenv(find_dotenv())

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
PASSWORD_SALT = os.getenv("PASSWORD_SALT", "sf-salt-2024")
DB_NAME = "sentinel_flow_demo"

client = MongoClient(MONGODB_URI)
db = client[DB_NAME]

rng = random.Random(42)


def hash_password(pwd: str) -> str:
    return hashlib.sha256(f"{PASSWORD_SALT}{pwd}".encode()).hexdigest()


def rand_date(days_ago_max: int, days_ago_min: int = 0) -> str:
    delta = timedelta(
        seconds=rng.randint(days_ago_min * 86400, days_ago_max * 86400)
    )
    return (datetime.utcnow() - delta).isoformat()


def gen_account_id(currency: str) -> str:
    prefix = {"TWD": "T", "USD": "U", "HKD": "H"}.get(currency, "X")
    return f"{prefix}{uuid.UUID(int=rng.getrandbits(128)).hex[:10].upper()}"


def gen_tx_id() -> str:
    return f"TX{uuid.UUID(int=rng.getrandbits(128)).hex[:12].upper()}"


def gen_event_id() -> str:
    return f"RE{uuid.UUID(int=rng.getrandbits(128)).hex[:10].upper()}"


# ── 1. Users (10) ────────────────────────────────────────────────────────────
USERS = [
    {
        "username": "admin",
        "name": "System Administrator",
        "role": "admin",
        "tier": "internal",
        "email": "admin@sentinelflow.io",
        "phone": "+886-2-0000-0000",
        "otp_enabled": False,
        "status": "active",
    },
    {
        "username": "john.doe",
        "name": "John Doe",
        "role": "user",
        "tier": "standard",
        "email": "john.doe@example.com",
        "phone": "+886-912-345-001",
        "otp_enabled": False,
        "status": "active",
    },
    {
        "username": "jane.smith",
        "name": "Jane Smith",
        "role": "user",
        "tier": "standard",
        "email": "jane.smith@example.com",
        "phone": "+886-912-345-002",
        "otp_enabled": True,
        "otp_code": "234567",
        "status": "active",
    },
    {
        "username": "michael.chen",
        "name": "Michael Chen",
        "role": "user",
        "tier": "vip",
        "email": "michael.chen@example.com",
        "phone": "+886-912-345-003",
        "otp_enabled": True,
        "otp_code": "345678",
        "status": "active",
    },
    {
        "username": "sarah.wong",
        "name": "Sarah Wong",
        "role": "user",
        "tier": "vip",
        "email": "sarah.wong@example.com",
        "phone": "+886-912-345-004",
        "otp_enabled": False,
        "status": "active",
    },
    {
        "username": "risk.user1",
        "name": "Alex Risk One",
        "role": "user",
        "tier": "standard",
        "email": "risk1@example.com",
        "phone": "+886-912-345-005",
        "otp_enabled": False,
        "status": "active",
    },
    {
        "username": "risk.user2",
        "name": "Alex Risk Two",
        "role": "user",
        "tier": "standard",
        "email": "risk2@example.com",
        "phone": "+886-912-345-006",
        "otp_enabled": False,
        "status": "locked",
    },
    {
        "username": "david.lee",
        "name": "David Lee",
        "role": "user",
        "tier": "standard",
        "email": "david.lee@example.com",
        "phone": "+886-912-345-007",
        "otp_enabled": False,
        "status": "active",
    },
    {
        "username": "emma.taylor",
        "name": "Emma Taylor",
        "role": "user",
        "tier": "standard",
        "email": "emma.taylor@example.com",
        "phone": "+886-912-345-008",
        "otp_enabled": True,
        "otp_code": "456789",
        "status": "active",
    },
    {
        "username": "risk_officer",
        "name": "Risk Officer Chen",
        "role": "risk_officer",
        "tier": "internal",
        "email": "risk.officer@sentinelflow.io",
        "phone": "+886-2-0000-0001",
        "otp_enabled": True,
        "otp_code": "567890",
        "status": "active",
    },
]

# ── 2. Accounts (20) ─────────────────────────────────────────────────────────
ACCOUNT_TEMPLATES = [
    # (username, currency, account_type, balance, status)
    ("john.doe",     "TWD", "savings",    350_000,    "active"),
    ("john.doe",     "USD", "savings",    12_000,     "active"),
    ("jane.smith",   "TWD", "checking",   85_000,     "active"),
    ("jane.smith",   "TWD", "savings",    1_200_000,  "active"),
    ("michael.chen", "TWD", "investment", 5_000_000,  "active"),
    ("michael.chen", "USD", "savings",    80_000,     "active"),
    ("michael.chen", "HKD", "savings",    200_000,    "active"),
    ("sarah.wong",   "TWD", "savings",    2_500_000,  "active"),
    ("sarah.wong",   "USD", "investment", 50_000,     "active"),
    ("sarah.wong",   "HKD", "checking",   75_000,     "active"),
    ("risk.user1",   "TWD", "savings",    1_500,      "active"),
    ("risk.user1",   "USD", "savings",    500,        "frozen"),
    ("risk.user2",   "TWD", "checking",   22_000,     "frozen"),
    ("david.lee",    "TWD", "savings",    450_000,    "active"),
    ("david.lee",    "TWD", "checking",   38_000,     "active"),
    ("emma.taylor",  "TWD", "savings",    680_000,    "active"),
    ("emma.taylor",  "USD", "savings",    25_000,     "pending_review"),
    ("admin",        "TWD", "savings",    10_000_000, "active"),
    ("john.doe",     "HKD", "savings",    15_000,     "pending_review"),
    ("jane.smith",   "HKD", "savings",    30_000,     "active"),
]

# ── 3. Transaction types / statuses ──────────────────────────────────────────
TX_TYPES     = ["transfer", "deposit", "withdrawal", "fx_exchange"]
TX_STATUSES  = ["completed"] * 7 + ["failed"] * 2 + ["pending"]
RISK_EVENT_TYPES = [
    ("LARGE_TRANSACTION",     "critical"),
    ("FREQUENT_TRANSFERS",    "high"),
    ("SUSPECTED_AML",         "critical"),
    ("UNUSUAL_LOGIN",         "medium"),
    ("FROZEN_ACCOUNT_DEBIT",  "critical"),
    ("STRUCTURING",           "high"),
    ("HIGH_RISK_COUNTRY",     "medium"),
    ("VELOCITY_BREACH",       "high"),
]
RISK_STATUSES = ["open"] * 4 + ["investigating"] * 3 + ["resolved"] * 3

NOTIF_TEMPLATES = [
    ("transaction_alert", "交易通知",    "您的帳戶發生一筆交易，金額："),
    ("risk_alert",        "風險告警",    "系統偵測到異常活動，請立即確認："),
    ("system_notice",     "系統公告",    "系統將於本週六凌晨 02:00 進行例行維護。"),
    ("account_alert",     "帳戶狀態更新", "您的帳戶狀態已更新為："),
    ("login_alert",       "登入通知",    "您的帳號已於新裝置登入，如非本人操作請立即聯繫客服。"),
]


def build_users(pw: str) -> list:
    hashed = hash_password(pw)
    now = rand_date(30)
    users = []
    for u in USERS:
        doc = {**u, "password_hash": hashed, "login_count": rng.randint(1, 120),
               "created_at": rand_date(365, 90), "last_login": now,
               "otp_fail_count": 0}
        users.append(doc)
    return users


def build_accounts() -> list:
    accounts = []
    for username, currency, acct_type, balance, status in ACCOUNT_TEMPLATES:
        acc_id = gen_account_id(currency)
        created = rand_date(365, 10)
        accounts.append({
            "account_id":      acc_id,
            "owner_username":  username,
            "currency":        currency,
            "account_type":    acct_type,
            "balance":         float(balance) + rng.uniform(-1000, 1000),
            "status":          status,
            "nickname":        None,
            "created_at":      created,
            "updated_at":      rand_date(30),
        })
    return accounts


def build_transactions(accounts: list) -> list:
    active_acc = [a for a in accounts if a["status"] in ("active", "pending_review")]
    all_ids    = [a["account_id"] for a in active_acc]
    txs = []

    for _ in range(100):
        tx_type = rng.choice(TX_TYPES)
        status  = rng.choice(TX_STATUSES)
        acc     = rng.choice(active_acc)
        amount  = round(rng.uniform(100, 500_000), 2)

        if tx_type == "transfer":
            others = [a for a in active_acc if a["account_id"] != acc["account_id"]]
            to_acc = rng.choice(others) if others else acc
            tx = {
                "transaction_id":   gen_tx_id(),
                "type":             "transfer",
                "from_account_id":  acc["account_id"],
                "to_account_id":    to_acc["account_id"],
                "amount":           amount,
                "currency":         acc["currency"],
                "memo":             rng.choice(["薪資轉帳", "房租", "水電費", "還款", "借款", ""]),
                "status":           status,
                "initiated_by":     acc["owner_username"],
                "flagged":          amount >= 500_000,
                "created_at":       rand_date(90),
            }
        elif tx_type == "deposit":
            tx = {
                "transaction_id":  gen_tx_id(),
                "type":            "deposit",
                "from_account_id": "EXTERNAL",
                "to_account_id":   acc["account_id"],
                "amount":          amount,
                "currency":        acc["currency"],
                "memo":            rng.choice(["ATM存款", "匯款入帳", "薪資入帳"]),
                "status":          status,
                "initiated_by":    acc["owner_username"],
                "flagged":         amount >= 500_000,
                "created_at":      rand_date(90),
            }
        elif tx_type == "withdrawal":
            tx = {
                "transaction_id":  gen_tx_id(),
                "type":            "withdrawal",
                "from_account_id": acc["account_id"],
                "to_account_id":   "EXTERNAL",
                "amount":          amount,
                "currency":        acc["currency"],
                "memo":            rng.choice(["ATM提款", "匯出", "現金提領"]),
                "status":          status,
                "initiated_by":    acc["owner_username"],
                "flagged":         amount >= 500_000,
                "created_at":      rand_date(90),
            }
        else:  # fx_exchange
            currencies = ["TWD", "USD", "HKD"]
            currencies.remove(acc["currency"]) if acc["currency"] in currencies else None
            to_cur = rng.choice(currencies)
            tx = {
                "transaction_id":  gen_tx_id(),
                "type":            "fx_exchange",
                "from_account_id": acc["account_id"],
                "to_account_id":   rng.choice(all_ids),
                "amount":          amount,
                "currency":        acc["currency"],
                "to_currency":     to_cur,
                "memo":            f"兌換 {to_cur}",
                "status":          status,
                "initiated_by":    acc["owner_username"],
                "flagged":         amount >= 500_000,
                "created_at":      rand_date(90),
            }
        txs.append(tx)
    return txs


def build_risk_events(accounts: list, txs: list) -> list:
    events = []
    usernames = list({a["owner_username"] for a in accounts})
    tx_ids = [t["transaction_id"] for t in txs]

    for i in range(30):
        event_type, severity = rng.choice(RISK_EVENT_TYPES)
        status = rng.choice(RISK_STATUSES)
        username = rng.choice(usernames)
        tx_id = rng.choice(tx_ids) if rng.random() > 0.3 else None

        desc_map = {
            "LARGE_TRANSACTION":    f"交易金額 {rng.randint(500_000, 5_000_000):,} TWD 超過 AML 門檻，需立即審查",
            "FREQUENT_TRANSFERS":   f"用戶 {username} 於 1 小時內發起 {rng.randint(10, 30)} 筆轉帳，疑似異常",
            "SUSPECTED_AML":        f"帳戶資金來源不明，交易模式符合洗錢特徵，風險評級：極高",
            "UNUSUAL_LOGIN":        f"用戶 {username} 從異地 IP 登入（{rng.choice(['美國', '俄羅斯', '奈及利亞', '中國'])}）",
            "FROZEN_ACCOUNT_DEBIT": "已凍結帳戶嘗試發起交易，疑似繞過管制",
            "STRUCTURING":          f"多筆 {rng.randint(90_000, 99_999):,} TWD 交易，疑似化整為零逃避申報",
            "HIGH_RISK_COUNTRY":    f"資金流向高風險國家帳戶，需進行增強盡職調查（EDD）",
            "VELOCITY_BREACH":      f"24 小時內交易量超過限額 {rng.randint(1_000_000, 5_000_000):,} TWD",
        }

        event = {
            "event_id":       gen_event_id(),
            "event_type":     event_type,
            "severity":       severity,
            "description":    desc_map.get(event_type, "異常活動偵測"),
            "username":       username,
            "transaction_id": tx_id,
            "status":         status,
            "created_at":     rand_date(90),
        }
        if status in ("resolved", "investigating"):
            event["reviewed_by"]  = "risk_officer"
            event["reviewed_at"]  = rand_date(10)
            event["review_notes"] = rng.choice(["已確認為正常交易", "持續監控中", "已通報法遵部門", "列為高關注帳戶"])
        events.append(event)
    return events


def build_notifications(accounts: list) -> list:
    usernames = list({a["owner_username"] for a in accounts})
    notifs = []
    for _ in range(50):
        username = rng.choice(usernames)
        tmpl = rng.choice(NOTIF_TEMPLATES)
        notif_type, title, base_msg = tmpl
        is_read = rng.random() > 0.45
        if notif_type == "transaction_alert":
            msg = base_msg + f"{rng.randint(1_000, 500_000):,} TWD"
        elif notif_type == "account_alert":
            msg = base_msg + rng.choice(["active（正常）", "pending_review（待審核）"])
        else:
            msg = base_msg
        notifs.append({
            "username":   username,
            "type":       notif_type,
            "title":      title,
            "message":    msg,
            "channel":    rng.choice(["system", "email", "sms"]),
            "is_read":    is_read,
            "metadata":   {},
            "created_at": rand_date(30),
        })
    return notifs


def main():
    print("=" * 55)
    print("  Sentinel Flow Demo — Seed Data Initializer")
    print("=" * 55)
    print(f"\n  DB      : {DB_NAME}")
    print(f"  URI     : {MONGODB_URI[:40]}...")
    print()

    # Clear collections
    for col in ("users", "accounts", "transactions", "risk_events", "notifications"):
        db[col].drop()
        print(f"  [CLEAR] {col}")

    # Build data
    users = build_users("Test1234!")
    accounts = build_accounts()
    transactions = build_transactions(accounts)
    risk_events = build_risk_events(accounts, transactions)
    notifications = build_notifications(accounts)

    # Insert
    db["users"].insert_many(users)
    db["accounts"].insert_many(accounts)
    db["transactions"].insert_many(transactions)
    db["risk_events"].insert_many(risk_events)
    db["notifications"].insert_many(notifications)

    print()
    print("  [INSERT] Results:")
    print(f"    users          : {db['users'].count_documents({})}")
    print(f"    accounts       : {db['accounts'].count_documents({})}")
    print(f"    transactions   : {db['transactions'].count_documents({})}")
    print(f"    risk_events    : {db['risk_events'].count_documents({})}")
    print(f"    notifications  : {db['notifications'].count_documents({})}")

    print()
    print("  Default password: Test1234!")
    print()
    print("  Test accounts:")
    for u in USERS:
        otp = f"  OTP: {u.get('otp_code', 'N/A')}" if u.get("otp_enabled") else ""
        print(f"    {u['username']:<20} role={u['role']:<14} status={u['status']}{otp}")

    print()
    print("  Done! Seed data created successfully.")
    print("=" * 55)


if __name__ == "__main__":
    main()
