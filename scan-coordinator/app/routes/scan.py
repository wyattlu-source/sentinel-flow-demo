"""
Scan Coordinator — 並行觸發 SAST + SCA，等待完成後正規化並產生報告。
Orchestrate 只需呼叫這一個服務。
"""
import os
import threading
import time
from datetime import datetime
from uuid import uuid4
from typing import Optional

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv, find_dotenv
from .projects import resolve_project

load_dotenv(find_dotenv())

router = APIRouter(tags=["Scan"])

# ── 下游服務位址 ──────────────────────────────────────────────────────────────
SAST_URL = "http://localhost:8011"
BD_URL   = "http://localhost:8006"
NORM_URL = "http://localhost:8014"
RPT_URL  = "http://localhost:8016"

# ── 預設值（讓 Orchestrate 不需要填每個參數）──────────────────────────────────
DEFAULT_REPO_PATH    = os.getenv("DEFAULT_REPO_PATH",
    r"C:\Users\Administrator\Desktop\Projects\sentinel-flow-demo")
DEFAULT_PROJECT_NAME = os.getenv("DEFAULT_PROJECT_NAME", "sentinel-flow-demo")
DEFAULT_BD_PROJECT   = os.getenv("BLACKDUCK_DEFAULT_PROJECT",
    "wyattlu-source/sentinel-flow-demo")
DEFAULT_BD_VERSION   = os.getenv("BLACKDUCK_DEFAULT_VERSION", "main")

_jobs: dict = {}


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    project_name:   Optional[str] = DEFAULT_PROJECT_NAME
    repo_path:      Optional[str] = DEFAULT_REPO_PATH
    bd_project:     Optional[str] = DEFAULT_BD_PROJECT
    bd_version:     Optional[str] = DEFAULT_BD_VERSION
    scan_mode:      Optional[str] = "full"   # full | incremental
    trigger_reason: Optional[str] = None     # e.g., "post_fix:req_xxx" | "manual" | "scheduled"
    # 只傳名稱時自動解析路徑（優先於 repo_path）
    project:        Optional[str] = None     # 只填名稱，例如 "sentinel-flow-demo"


# ── 輪詢工具 ──────────────────────────────────────────────────────────────────

def _poll(url: str, done_statuses: set, interval: int = 15, timeout: int = 1800):
    """持續 GET url，直到 status 在 done_statuses 或超時。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=10)
            if r.ok:
                data = r.json()
                if data.get("status") in done_statuses:
                    return data.get("status"), data
        except Exception:
            pass
        time.sleep(interval)
    return "timeout", {}


# ── 主掃描流程（背景執行） ────────────────────────────────────────────────────

def _run_scan(job_id: str, req: ScanRequest):
    job = _jobs[job_id]

    # ── STEP 1：同時觸發兩個掃描 ─────────────────────────────────────────────
    job["step"] = "triggering"
    sast_job_id = bd_job_id = None

    try:
        r = requests.post(f"{SAST_URL}/sast/scan", json={
            "repo_path": req.repo_path,
            "scan_mode": req.scan_mode,
        }, timeout=30)
        sast_job_id = r.json().get("job_id")
        job["sast_job_id"] = sast_job_id
    except Exception as e:
        job["sast_trigger_error"] = str(e)

    try:
        r = requests.post(f"{BD_URL}/blackduck/scan/trigger",
                          params={"source_path": req.repo_path}, timeout=30)
        bd_job_id = r.json().get("job_id")
        job["bd_job_id"] = bd_job_id
    except Exception as e:
        job["bd_trigger_error"] = str(e)

    # ── STEP 2：並行等待兩個掃描完成 ─────────────────────────────────────────
    job["step"] = "scanning"
    sast_status = sast_data = bd_status = bd_data = None

    results = {}

    def wait_sast():
        if not sast_job_id:
            return
        s, d = _poll(f"{SAST_URL}/sast/status/{sast_job_id}",
                     done_statuses={"completed", "failed", "timeout"})
        results["sast_status"] = s
        results["sast_data"]   = d

    def wait_bd():
        if not bd_job_id:
            return
        s, d = _poll(f"{BD_URL}/blackduck/scan/status/{bd_job_id}",
                     done_statuses={"completed", "failed"})
        results["bd_status"] = s
        results["bd_data"]   = d

    t1 = threading.Thread(target=wait_sast, daemon=True)
    t2 = threading.Thread(target=wait_bd,   daemon=True)
    t1.start(); t2.start()
    t1.join(timeout=1850); t2.join(timeout=1850)

    sast_status = results.get("sast_status", "timeout")
    sast_data   = results.get("sast_data",   {})
    bd_status   = results.get("bd_status",   "timeout")
    bd_data     = results.get("bd_data",     {})

    job["sast_status"] = sast_status
    job["bd_status"]   = bd_status

    # ── STEP 3：正規化兩個結果 ────────────────────────────────────────────────
    job["step"] = "normalizing"
    sast_vulns = []
    sca_vulns  = []

    if sast_status == "completed" and sast_data:
        try:
            r = requests.post(f"{NORM_URL}/normalize/sast",
                              json=sast_data, timeout=30)
            sast_vulns = r.json().get("vulnerabilities", [])
        except Exception as e:
            job["sast_norm_error"] = str(e)

    if bd_status == "completed":
        try:
            r = requests.post(f"{NORM_URL}/normalize/sca", json={
                "project": req.bd_project,
                "version": req.bd_version,
            }, timeout=60)
            sca_vulns = r.json().get("vulnerabilities", [])
        except Exception as e:
            job["sca_norm_error"] = str(e)

    # ── STEP 4：產生報告 ──────────────────────────────────────────────────────
    job["step"] = "reporting"
    try:
        r = requests.post(f"{RPT_URL}/report/generate", json={
            "scan_id":        job_id,
            "project_name":   req.project_name,
            "sast_vulns":     sast_vulns,
            "sca_vulns":      sca_vulns,
            "trigger_reason": req.trigger_reason or "manual",
        }, timeout=30)
        report = r.json()
    except Exception as e:
        report = {"error": str(e), "sast_vulns": sast_vulns, "sca_vulns": sca_vulns}

    job.update({
        "status":       "completed",
        "step":         "done",
        "report":       report,
        "completed_at": datetime.now().isoformat(),
    })


# ── API Endpoints ─────────────────────────────────────────────────────────────

@router.post("/start", summary="啟動 SAST + SCA 完整安全掃描", operation_id="startScan")
def start_scan(req: ScanRequest):
    """
    並行觸發 SAST（白箱）與 SCA（Black Duck 套件）兩種掃描。
    回傳 scan_id，用 /scan/status/{scan_id} 查詢進度。
    完成後用 /scan/report/{scan_id} 取得完整報告。
    """
    # 若只傳專案名稱，自動解析路徑
    if req.project:
        info = resolve_project(req.project)
        if not info["exists"]:
            raise HTTPException(status_code=404,
                detail=f"找不到專案 '{req.project}'，請確認路徑 {info['path']} 存在。")
        req.project_name = req.project
        req.repo_path    = info["path"]
        req.bd_project   = info["bd_project"]

    scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:6]}"
    _jobs[scan_id] = {
        "status":         "running",
        "step":           "triggering",
        "project_name":   req.project_name,
        "scan_mode":      req.scan_mode,
        "trigger_reason": req.trigger_reason or "manual",
        "started_at":     datetime.now().isoformat(),
    }
    threading.Thread(target=_run_scan, args=(scan_id, req), daemon=True).start()
    return {
        "scan_id":   scan_id,
        "status":    "running",
        "started_at": _jobs[scan_id]["started_at"],
        "message":   "SAST + SCA 掃描已啟動，請用 /scan/status/{scan_id} 查詢進度",
    }


@router.get("/status/{scan_id}", summary="查詢掃描進度", operation_id="getScanStatus")
def get_status(scan_id: str):
    """
    step: triggering → scanning → normalizing → reporting → done
    status: running → completed
    """
    job = _jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"scan_id '{scan_id}' not found")
    return {"scan_id": scan_id, **job}


@router.get("/report/{scan_id}", summary="取得掃描報告", operation_id="getScanReport")
def get_report(scan_id: str):
    """取得完整掃描報告（SAST + SCA 彙整）。掃描完成後才有內容。"""
    job = _jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"scan_id '{scan_id}' not found")
    if job.get("status") != "completed":
        return {"scan_id": scan_id, "status": job.get("status"),
                "step": job.get("step"), "message": "掃描尚未完成"}
    return {"scan_id": scan_id, **job.get("report", {})}


@router.get("/list", summary="列出所有掃描工作")
def list_scans():
    return {"total": len(_jobs), "scans": [
        {"scan_id": k, "status": v.get("status"), "step": v.get("step"),
         "project": v.get("project_name"), "started_at": v.get("started_at")}
        for k, v in _jobs.items()
    ]}
