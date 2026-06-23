"""
Report Service — 彙整 SAST + SCA 正規化結果，產生統一安全掃描報告。
報告格式：JSON（可直接回傳給 Orchestrate 或存檔）。
掃描完成後自動發布到 Kafka topic: blackduck-log
"""

import json
import os
import re
import threading
from datetime import datetime
from typing import Any, List, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# 報告儲存目錄
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ── Kafka 設定 ────────────────────────────────────────────────────────────────
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "10.107.85.239:9092")
KAFKA_TOPIC     = os.getenv("KAFKA_TOPIC", "blackduck-log")

# ── Email 通知設定（PLACEHOLDER — 等待 API Key） ───────────────────────────────
NOTIFY_EMAIL  = os.getenv("NOTIFY_EMAIL", "")    # 收件人，例如 sc856036@gmail.com
EMAIL_API_KEY = os.getenv("EMAIL_API_KEY", "")   # Email 服務 API Key（SendGrid / Resend）
EMAIL_FROM    = os.getenv("EMAIL_FROM", "")       # 寄件人地址


def _send_email_notification(report: dict) -> None:
    """
    📧 EMAIL PLACEHOLDER — 尚未實作，等待 EMAIL_API_KEY 設定後啟用。

    計畫寄送內容：
      主旨 : [SentinelFlow] 安全掃描完成 - {project_name}
      收件 : NOTIFY_EMAIL 環境變數
      內容 :
        - 掃描時間 / scan_id
        - 觸發原因（post_fix:req_xxx 表示修復後重新掃描）
        - HIGH + CRITICAL 漏洞數量
        - 修復前後比較（若 trigger_reason 含 "post_fix"）
        - 報告連結

    支援的 Email 服務（擇一實作）：
      - Resend  : https://resend.com  (推薦，免費方案夠用)
      - SendGrid: https://sendgrid.com
      - SMTP    : 使用 smtplib + TLS

    待接入：
      NOTIFY_EMAIL  = 收件人 email
      EMAIL_API_KEY = Email 服務 API Key
      EMAIL_FROM    = 寄件人地址
    """
    if not NOTIFY_EMAIL or not EMAIL_API_KEY:
        print(
            f"[Email] PLACEHOLDER — NOTIFY_EMAIL={NOTIFY_EMAIL or '(未設定)'} "
            f"EMAIL_API_KEY={'(已設定)' if EMAIL_API_KEY else '(未設定)'} → 略過"
        )
        return

    # ── TODO: 在此實作 email 發送 ─────────────────────────────────────────────
    # 範例（Resend）：
    # import httpx
    # trigger = report.get("trigger_reason", "manual")
    # is_post_fix = "post_fix" in trigger
    # high_count = report.get("summary", {}).get("by_severity", {}).get("high", 0)
    # crit_count = report.get("summary", {}).get("by_severity", {}).get("critical", 0)
    # subject = f"[SentinelFlow] {'修復後重新掃描' if is_post_fix else '安全掃描'} 完成 — {report.get('project_name')}"
    # httpx.post(
    #     "https://api.resend.com/emails",
    #     headers={"Authorization": f"Bearer {EMAIL_API_KEY}"},
    #     json={
    #         "from": EMAIL_FROM,
    #         "to": [NOTIFY_EMAIL],
    #         "subject": subject,
    #         "html": f"<p>HIGH: {high_count}, CRITICAL: {crit_count}</p><p>scan_id: {report.get('scan_id')}</p>",
    #     }
    # )
    print(f"[Email] TODO: 寄送通知至 {NOTIFY_EMAIL}  scan_id={report.get('scan_id')}")


def _publish_to_kafka(report: dict):
    """背景執行：將報告發布到 Kafka topic blackduck-log"""
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
            key_serializer=lambda k: k.encode("utf-8") if k else None,
            request_timeout_ms=10000,
            retries=3,
        )
        key = report.get("scan_id", "unknown")
        future = producer.send(KAFKA_TOPIC, key=key, value=report)
        future.get(timeout=10)
        producer.flush()
        producer.close()
        print(f"[Kafka] Published scan_id={key} to topic={KAFKA_TOPIC}")
    except Exception as e:
        print(f"[Kafka] Publish failed: {e}")

app = FastAPI(
    title="Report Service",
    description="彙整 SAST + SCA 掃描結果，產生統一安全報告。",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ────────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    scan_id:        str
    project_name:   str
    sast_vulns:     Optional[List[Any]] = []
    sca_vulns:      Optional[List[Any]] = []
    trigger_reason: Optional[str] = "manual"  # "manual" | "post_fix:req_xxx" | "scheduled"


# ── 工具函式 ──────────────────────────────────────────────────────────────────

def _count_by_severity(vulns: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "audit": 0, "unknown": 0}
    for v in vulns:
        s = v.get("severity", "unknown").lower()
        counts[s] = counts.get(s, 0) + 1
    return counts


def _top_findings(vulns: list, n: int = 5) -> list:
    """回傳嚴重程度最高的前 N 筆。"""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "audit": 4, "unknown": 5}
    sorted_v = sorted(vulns, key=lambda v: order.get(v.get("severity", "unknown"), 5))
    return sorted_v[:n]


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "report-service", "port": 8016, "version": "1.0.0"}


@app.post("/report/generate", summary="產生安全掃描彙整報告")
def generate_report(req: ReportRequest):
    """
    接收 normalizer 輸出的 SAST + SCA 漏洞清單，
    產生彙整報告並存到 report-service/reports/。
    """
    sast_vulns = req.sast_vulns or []
    sca_vulns  = req.sca_vulns  or []
    all_vulns  = sast_vulns + sca_vulns

    sast_by_sev = _count_by_severity(sast_vulns)
    sca_by_sev  = _count_by_severity(sca_vulns)
    total_by_sev = _count_by_severity(all_vulns)

    # 依類型分組（SAST checker 或 SCA CVE）
    type_counter: dict = {}
    for v in all_vulns:
        t = v.get("type", "UNKNOWN")
        type_counter[t] = type_counter.get(t, 0) + 1
    top_types = sorted(type_counter.items(), key=lambda x: -x[1])[:10]

    report = {
        "scan_id":        req.scan_id,
        "project_name":   req.project_name,
        "generated_at":   datetime.now().isoformat(),
        "trigger_reason": req.trigger_reason or "manual",

        # ── 總覽 ──────────────────────────────────────────────────────────────
        "summary": {
            "total_vulnerabilities": len(all_vulns),
            "by_severity":           total_by_sev,
            "sast": {
                "total":       len(sast_vulns),
                "by_severity": sast_by_sev,
            },
            "sca": {
                "total":       len(sca_vulns),
                "by_severity": sca_by_sev,
            },
            "top_issue_types": [{"type": t, "count": c} for t, c in top_types],
        },

        # ── 重點發現（前 5 筆最嚴重） ─────────────────────────────────────────
        "top_findings": _top_findings(all_vulns, n=5),

        # ── 完整清單 ──────────────────────────────────────────────────────────
        "sast_findings": sast_vulns,
        "sca_findings":  sca_vulns,
    }

    # 存檔
    ts       = datetime.now().strftime("%Y%m%d_%H%M")
    safe_scan_id = re.sub(r'[^A-Za-z0-9_-]', '', req.scan_id)[:8]
    filename = f"{ts}_full_{safe_scan_id}.json"
    filepath = os.path.join(REPORTS_DIR, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        report["report_path"] = os.path.abspath(filepath)
    except Exception as e:
        report["report_save_error"] = str(e)

    # 發布到 Kafka（背景，不阻塞 API 回應）
    threading.Thread(
        target=_publish_to_kafka,
        args=(report,),
        daemon=True,
    ).start()

    # 📧 Email 通知（背景，PLACEHOLDER — 等待 EMAIL_API_KEY 設定後自動啟用）
    threading.Thread(
        target=_send_email_notification,
        args=(report,),
        daemon=True,
    ).start()

    return report
