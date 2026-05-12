"""
Analysis Message Collector
Orchestrate 把掃描分析結果存到 .analysis-messages/，
由 claude_auto_fix.py 自動讀取並用 Claude Code CLI 修復程式碼。
"""

import json
import os
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel
from fastapi import HTTPException

_SERVICE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVICE_DIR)
ANALYSIS_DIR = Path(_PROJECT_DIR) / ".analysis-messages"
ANALYSIS_DIR.mkdir(exist_ok=True)


# ── Models ────────────────────────────────────────────────────────────────────

class AnalysisMessage(BaseModel):
    source: str = "orchestrate"
    message_type: str      # vulnerability_analysis | scan_result | recommendation
    content: str           # 分析的完整內容，Claude 會讀這裡決定要修什麼
    project_name: Optional[str] = None
    version: Optional[str] = None
    severity: Optional[str] = None
    metadata: Optional[dict] = None


class AnalysisResponse(BaseModel):
    message_id: str
    status: str
    timestamp: str
    message: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _save(data: dict) -> str:
    message_id = f"msg_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    data["message_id"]  = message_id
    data["received_at"] = datetime.now().isoformat()
    data["processed"]   = False
    (ANALYSIS_DIR / f"{message_id}.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return message_id


def _load_all(processed: Optional[bool] = None) -> List[dict]:
    result = []
    for f in ANALYSIS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if processed is None or data.get("processed") == processed:
                result.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    result.sort(key=lambda x: x.get("received_at", ""), reverse=True)
    return result


# ── API Handlers ──────────────────────────────────────────────────────────────

def collect_analysis_message(message: AnalysisMessage):
    """
    Orchestrate 呼叫此端點送出分析訊息。
    訊息儲存後，claude_auto_fix.py 會自動讀取並用 Claude Code CLI 修復程式碼。
    """
    try:
        message_id = _save(message.dict())
        return AnalysisResponse(
            message_id=message_id,
            status="received",
            timestamp=datetime.now().isoformat(),
            message=f"Message {message_id} saved. Claude Code CLI will auto-process it.",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def list_analysis_messages(processed: Optional[bool] = None):
    try:
        msgs = _load_all(processed)
        return {"total": len(msgs), "messages": msgs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def get_unprocessed_messages():
    try:
        msgs = _load_all(processed=False)
        return {"total": len(msgs), "messages": msgs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
