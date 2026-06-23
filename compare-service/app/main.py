from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Any
from datetime import datetime

app = FastAPI(
    title="Compare Service",
    description="比對修復前後的掃描結果，計算修復率與殘留漏洞。",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CompareRequest(BaseModel):
    scan_id: str
    before: List[Any] = []
    after: List[Any] = []


@app.get("/health")
def health():
    return {"status": "ok", "service": "compare-service", "port": 8015}


@app.post("/compare", summary="比對修復前後漏洞差異")
def compare(req: CompareRequest):
    """
    比對 before_fix / after_fix 的 VulnerabilityItem 清單。
    計算：已修復數、殘留數、新增數、修復率。

    TODO: 實作比對邏輯（以 cve_id + component 為 key）
    """
    return {
        "scan_id": req.scan_id,
        "compared_at": datetime.now().isoformat(),
        "before_count": len(req.before),
        "after_count": len(req.after),
        "fixed_count": 0,
        "remaining_count": 0,
        "fix_rate": "0%",
        "status": "stub",
        "note": "stub — 尚未實作比對邏輯",
    }
