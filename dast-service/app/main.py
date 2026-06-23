from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

app = FastAPI(
    title="DAST Service",
    description="黑箱掃描服務：使用 Nuclei 掃描 Web / API endpoint。目前為 stub。",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DastRequest(BaseModel):
    scan_id: str
    target_url: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "dast-service", "port": 8012}


@app.post("/dast/scan", summary="觸發 DAST 黑箱掃描")
def start_dast(req: DastRequest):
    """
    使用 Nuclei 掃描指定 URL。
    回傳統一格式的漏洞清單。

    TODO: subprocess 呼叫 nuclei.exe，解析 JSON 輸出，轉換為 VulnerabilityItem 格式
    """
    return {
        "scan_id": req.scan_id,
        "scan_type": "dast",
        "status": "stub",
        "target_url": req.target_url,
        "scanned_at": datetime.now().isoformat(),
        "vulnerabilities": [],
        "note": "stub — 尚未實作 Nuclei 整合",
    }
