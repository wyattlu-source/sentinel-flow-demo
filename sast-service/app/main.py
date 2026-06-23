"""
SAST Service — 透過 GitHub + WinRM 在 10.107.85.80 執行 Coverity 白箱掃描。

傳輸方案：GitHub git clone / pull（取代舊版 WinRM Copy-Item）
流程：
  1. 本機 git push 把最新程式碼推到 GitHub
  2. WinRM 叫 80 VM 執行 git clone（第一次）或 git pull（之後）
  3. 在 80 VM 執行 Coverity 掃描（full 或 incremental）
  4. WinRM 把 result.json 拉回來，自動存到 reports/
  5. 解析 JSON，回傳漏洞摘要

環境變數（.env）：
  COVERITY_REMOTE_HOST      遠端 VM IP，預設 10.107.85.80
  COVERITY_REMOTE_USER      遠端登入帳號，預設 Administrator
  COVERITY_REMOTE_PASSWORD  遠端登入密碼
  COVERITY_REMOTE_WORKSPACE 遠端工作目錄，預設 C:\\coverity-workspace
  COVERITY_YAML_PATH        本機 coverity.yaml 路徑
  GITHUB_REPO_URL           GitHub repo URL（空白時從 repo_path 自動偵測）
  GIT_BRANCH                掃描分支，預設 main
"""

import json
import os
import subprocess
import threading
import uuid
from datetime import datetime
from typing import Optional, List, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

# ── Coverity 遠端設定 ──────────────────────────────────────────────────────────
REMOTE_HOST      = os.getenv("COVERITY_REMOTE_HOST",      "10.107.85.80")
REMOTE_USER      = os.getenv("COVERITY_REMOTE_USER",      "Administrator")
REMOTE_PASSWORD  = os.getenv("COVERITY_REMOTE_PASSWORD",  "")
REMOTE_WORKSPACE = os.getenv("COVERITY_REMOTE_WORKSPACE", r"C:\coverity-workspace")
COVERITY_YAML    = os.getenv("COVERITY_YAML_PATH",
    r"C:\Users\Administrator\Desktop\Projects\coverity.yaml")

# ── GitHub 設定 ────────────────────────────────────────────────────────────────
GITHUB_REPO_URL = os.getenv("GITHUB_REPO_URL", "")
GIT_BRANCH      = os.getenv("GIT_BRANCH", "main")

# ── 本機報告目錄（自動存檔） ──────────────────────────────────────────────────
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

_scan_jobs: dict = {}

app = FastAPI(
    title="SAST Service",
    description="白箱掃描服務：GitHub git clone/pull + WinRM + Coverity，支援 full / incremental 掃描。",
    version="3.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ────────────────────────────────────────────────────────────────────

class SastRequest(BaseModel):
    scan_id:   Optional[str] = None
    repo_path: str
    repo_url:  Optional[str] = None
    scan_mode: Literal["full", "incremental"] = "full"
    """
    full        — 刪除 idir 重建，完整掃描所有檔案（預設）
    incremental — 保留 idir，只掃 git diff 的部分，速度較快
    """


class CheckerResult(BaseModel):
    checker: str
    count:   int


# ── 工具函式 ──────────────────────────────────────────────────────────────────

def _detect_repo_url(repo_path: str) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", repo_path, "remote", "get-url", "origin"],
            capture_output=True, text=True, timeout=10,
        )
        url = r.stdout.strip()
        if url:
            return url
    except Exception:
        pass
    return GITHUB_REPO_URL


def _git_push(repo_path: str, branch: str) -> tuple:
    try:
        r = subprocess.run(
            ["git", "-C", repo_path, "push", "origin", branch],
            capture_output=True, text=True, timeout=120,
        )
        out = (r.stdout + r.stderr).strip()
        return r.returncode == 0, out
    except Exception as e:
        return False, str(e)


def _parse_result(result_path: str) -> list:
    """
    解析 Coverity --local-format json 輸出，回傳 [{checker, count}]。
    """
    try:
        with open(result_path, encoding="utf-8") as f:
            data = json.load(f)
        issues = data.get("issues", [])
        counter: dict = {}
        for issue in issues:
            name = issue.get("checkerName") or issue.get("checker") or "UNKNOWN"
            counter[name] = counter.get(name, 0) + 1
        return [{"checker": k, "count": v} for k, v in sorted(counter.items())]
    except Exception:
        return []


def _save_report(result_path: str, job_id: str, scan_mode: str) -> str:
    """把 result.json 存一份到 reports/ 目錄，回傳儲存路徑。"""
    try:
        ts        = datetime.now().strftime("%Y%m%d_%H%M")
        mode_short = "incr" if scan_mode == "incremental" else "full"
        filename  = f"{ts}_{mode_short}.json"
        dest = os.path.join(REPORTS_DIR, filename)
        with open(result_path, encoding="utf-8") as f:
            data = json.load(f)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return dest
    except Exception:
        return ""


# ── 遠端掃描邏輯 ──────────────────────────────────────────────────────────────

def _run_coverity(job_id: str, repo_path: str, repo_url: str, scan_mode: str):
    """
    full mode:
      - git 重新 reset --hard（確保完整）
      - 刪除 idir → Coverity 完整重掃

    incremental mode:
      - git pull（只傳 diff）
      - 保留 idir → Coverity 只掃有變更的部分（--incremental）
    """
    project_name  = os.path.basename(repo_path.rstrip("\\/")) or "project"
    remote_target = f"{REMOTE_WORKSPACE}\\{project_name}"
    remote_idir   = f"{remote_target}\\idir"
    remote_report = f"{remote_target}\\report"

    is_full = (scan_mode == "full")

    # ── Step 0：本機 git push ────────────────────────────────────────────────
    _scan_jobs[job_id]["step"] = "git push"
    push_ok, push_msg = _git_push(repo_path, GIT_BRANCH)
    if not push_ok:
        if "up-to-date" not in push_msg.lower() and "up to date" not in push_msg.lower():
            _scan_jobs[job_id].update({
                "status": "failed",
                "error": f"git push failed: {push_msg}",
            })
            return

    pw = REMOTE_PASSWORD.replace("'", "''")

    # ── PowerShell 腳本：依 scan_mode 分支 ───────────────────────────────────
    if is_full:
        git_sync_block = f"""
    # ── full mode: 刪除 idir，強制重置整個工作目錄 ────────────────────────────
    if (Test-Path '{remote_target}\\.git') {{
        Write-Host "[1/3] git reset --hard (full mode)..."
        Set-Location '{remote_target}'
        if (Test-Path '{remote_idir}')   {{ Remove-Item '{remote_idir}'   -Recurse -Force; Write-Host "idir cleared." }}
        if (Test-Path '{remote_report}') {{ Remove-Item '{remote_report}' -Recurse -Force }}
        git fetch origin 2>&1
        git reset --hard origin/{GIT_BRANCH} 2>&1
        git clean -fd 2>&1
    }} else {{
        Write-Host "[1/3] git clone (first time, full mode)..."
        if (Test-Path '{remote_target}') {{ Remove-Item '{remote_target}' -Recurse -Force }}
        New-Item -ItemType Directory -Path '{REMOTE_WORKSPACE}' -Force | Out-Null
        git clone --branch {GIT_BRANCH} '{repo_url}' '{remote_target}' 2>&1
    }}"""
        coverity_flag = ""  # full scan = no flag
    else:
        git_sync_block = f"""
    # ── incremental mode: 保留 idir，只 pull diff ─────────────────────────────
    if (Test-Path '{remote_target}\\.git') {{
        Write-Host "[1/3] git pull (incremental mode - diff only)..."
        Set-Location '{remote_target}'
        if (Test-Path '{remote_report}') {{ Remove-Item '{remote_report}' -Recurse -Force }}
        git fetch origin 2>&1
        git reset --hard origin/{GIT_BRANCH} 2>&1
        git clean -fd 2>&1
        Write-Host "idir preserved for incremental analysis."
    }} else {{
        Write-Host "[1/3] git clone (first time, will switch to incremental next run)..."
        if (Test-Path '{remote_target}') {{ Remove-Item '{remote_target}' -Recurse -Force }}
        New-Item -ItemType Directory -Path '{REMOTE_WORKSPACE}' -Force | Out-Null
        git clone --branch {GIT_BRANCH} '{repo_url}' '{remote_target}' 2>&1
    }}"""
        coverity_flag = "--incremental"

    ps_cmd = f"""
$ErrorActionPreference = 'Stop'
$secpwd  = ConvertTo-SecureString '{pw}' -AsPlainText -Force
$cred    = New-Object System.Management.Automation.PSCredential('{REMOTE_USER}', $secpwd)
$session = New-PSSession -ComputerName '{REMOTE_HOST}' -Credential $cred

# ============================================================
# STEP 1: git sync ({scan_mode} mode)
# ============================================================
Invoke-Command -Session $session -ScriptBlock {{
    $env:PATH = 'C:\\Program Files\\Git\\bin;C:\\Program Files\\Git\\cmd;' + $env:PATH
    {git_sync_block}
    if ($LASTEXITCODE -ne 0) {{ throw "git failed (exit $LASTEXITCODE)" }}
    Write-Host "Git sync complete."
}}

# ============================================================
# STEP 2: copy coverity.yaml (single small file via WinRM)
# ============================================================
Write-Host "[2/3] Copying coverity.yaml..."
Copy-Item -Path '{COVERITY_YAML}' `
          -Destination '{remote_target}\\coverity.yaml' `
          -ToSession $session -Force

# ============================================================
# STEP 3: coverity scan ({scan_mode})
# ============================================================
Write-Host "[3/3] Running Coverity scan (mode={scan_mode})..."
$exitCode = Invoke-Command -Session $session -ScriptBlock {{
    if (Test-Path '{remote_target}\\.git') {{
        Remove-Item '{remote_target}\\.git' -Recurse -Force
    }}
    Set-Location '{remote_target}'
    coverity scan -c coverity.yaml --dir '{remote_idir}' {coverity_flag} --local '{remote_report}' --local-format json --project-dir '.' 2>&1 | Tee-Object -Variable scanOut
    Write-Host $scanOut
    $LASTEXITCODE
}}

# ============================================================
# STEP 4: pull result.json back
# ============================================================
$localTemp = "$env:TEMP\\coverity_result_{job_id}.json"
Copy-Item -Path '{remote_report}' `
          -Destination $localTemp `
          -FromSession $session

Remove-PSSession $session
Write-Host "EXIT:$exitCode"
Write-Host "SUMMARY_PATH:$localTemp"
"""

    try:
        _scan_jobs[job_id]["step"] = "coverity scan"
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=1200,
        )
        output = (result.stdout or "") + (result.stderr or "")

        if result.returncode != 0:
            _scan_jobs[job_id].update({"status": "failed", "error": output[-2000:]})
            return

        result_path = None
        for line in output.splitlines():
            if line.startswith("SUMMARY_PATH:"):
                result_path = line.split(":", 1)[1].strip()
                break

        if not result_path or not os.path.exists(result_path):
            _scan_jobs[job_id].update({"status": "failed", "error": "result file not found"})
            return

        # ── 自動存報告 ──────────────────────────────────────────────────────
        saved_path = _save_report(result_path, job_id, scan_mode)

        # ── 解析摘要 ─────────────────────────────────────────────────────────
        checkers = _parse_result(result_path)
        total    = sum(c["count"] for c in checkers)

        _scan_jobs[job_id].update({
            "status":       "completed",
            "total":        total,
            "checkers":     checkers,
            "report_path":  saved_path,
            "completed_at": datetime.now().isoformat(),
        })

        try:
            os.remove(result_path)
        except OSError:
            pass

    except subprocess.TimeoutExpired:
        _scan_jobs[job_id].update({"status": "timeout"})
    except Exception as e:
        _scan_jobs[job_id].update({"status": "failed", "error": str(e)})


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status":        "ok",
        "service":       "sast-service",
        "version":       "3.0.0",
        "port":          8011,
        "remote_host":   REMOTE_HOST,
        "transfer_mode": "GitHub git clone/pull",
        "git_branch":    GIT_BRANCH,
        "repo_url":      GITHUB_REPO_URL or "(auto-detect from repo_path)",
        "reports_dir":   os.path.abspath(REPORTS_DIR),
    }


@app.post("/sast/scan", response_model=dict, summary="觸發 Coverity 白箱掃描")
def start_sast(req: SastRequest):
    """
    scan_mode:
    - **full** (預設)：刪除 idir 重建，完整掃描所有檔案
    - **incremental**：保留 idir，只掃 git diff 有變更的部分，速度較快

    掃描完成後報告自動存到 sast-service/reports/。
    """
    if not os.path.exists(req.repo_path):
        raise HTTPException(status_code=400, detail=f"路徑不存在：{req.repo_path}")

    repo_url = req.repo_url or GITHUB_REPO_URL or _detect_repo_url(req.repo_path)
    if not repo_url:
        raise HTTPException(
            status_code=400,
            detail="無法取得 GitHub repo URL，請在 .env 設定 GITHUB_REPO_URL",
        )

    job_id = req.scan_id or uuid.uuid4().hex[:8]
    _scan_jobs[job_id] = {
        "status":        "running",
        "step":          "git push",
        "scan_mode":     req.scan_mode,
        "project_path":  req.repo_path,
        "repo_url":      repo_url,
        "started_at":    datetime.now().isoformat(),
        "transfer_mode": "GitHub git clone/pull",
    }

    threading.Thread(
        target=_run_coverity,
        args=(job_id, req.repo_path, repo_url, req.scan_mode),
        daemon=True,
    ).start()

    return {
        "job_id":        job_id,
        "status":        "running",
        "scan_mode":     req.scan_mode,
        "started_at":    _scan_jobs[job_id]["started_at"],
        "project_path":  req.repo_path,
        "repo_url":      repo_url,
    }


@app.get("/sast/status/{job_id}", summary="查詢掃描狀態與結果")
def get_sast_status(job_id: str):
    """
    status: running → completed / failed / timeout
    step:   git push → coverity scan
    完成後包含 total、checkers、report_path
    """
    job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' 不存在")
    return {"job_id": job_id, **job}


@app.get("/sast/jobs", summary="列出所有掃描工作")
def list_jobs():
    return {"total": len(_scan_jobs), "jobs": [
        {
            "job_id":     k,
            "status":     v.get("status"),
            "scan_mode":  v.get("scan_mode"),
            "step":       v.get("step"),
            "project":    v.get("project_path"),
            "started_at": v.get("started_at"),
            "report":     v.get("report_path", ""),
        }
        for k, v in _scan_jobs.items()
    ]}
