"""
Fix Filter — 從掃描報告過濾高風險漏洞，整理成 Bob 可直接讀取的修復指令 JSON。

流程：
  scan_id → 取得完整報告 → 過濾 HIGH/CRITICAL → 分類 SCA/SAST
  → 產生結構化 fix plan → (可選) 自動送給 Bob 執行
"""
import os
import glob
import json
import requests
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from .projects import resolve_project

router = APIRouter(tags=["Fix"])

# ── 服務位址 ──────────────────────────────────────────────────────────────────
REPORT_SVC   = "http://localhost:8016"
CODE_MOD_URL = "http://localhost:8006/code-modification/request"

# ── 設定 ──────────────────────────────────────────────────────────────────────
HIGH_RISK        = {"critical", "high"}
SEVERITY_ORDER   = {"critical": 0, "high": 1, "medium": 2, "low": 3, "audit": 4}

# PyPI 名稱映射（Black Duck 回傳的名稱有時與 PyPI 不同）
_PYPI_NAME_MAP = {
    "pyca/cryptography": "cryptography",
    "python-jwt":        "PyJWT",
}


def _get_safe_version(package_name: str) -> str:
    """查詢 PyPI 取得最新穩定版本號。失敗時回傳空字串。"""
    pypi_name = _PYPI_NAME_MAP.get(package_name, package_name)
    try:
        r = requests.get(
            f"https://pypi.org/pypi/{pypi_name}/json",
            timeout=8,
        )
        if r.ok:
            return r.json()["info"]["version"]
    except Exception:
        pass
    return ""

# 掃描報告存放目錄（report-service）
_REPORT_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "report-service", "reports"
)

# 專案根目錄（搜尋 requirements.txt 用）
_PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..")

# SAST：有明確自動修復方式的問題類型
SAST_FIX_GUIDE = {
    "SIGMA.cors_with_credentials_all_origin": (
        "Fix CORS misconfiguration (CWE-942): change allow_origins=[\"*\"] to a "
        "concrete whitelist of trusted origins (e.g. "
        "[\"http://localhost:3000\", \"http://localhost:8000\"]) AND set "
        "allow_credentials=False. Wildcard origin alone is still flagged High by "
        "the scanner even with allow_credentials=False — both changes are required."
    ),
    "SIGMA.hardcoded_secret": (
        "Move hardcoded secret/password to environment variable (.env file)"
    ),
    "NULL_RETURNS": (
        "Add null/None check before using the return value of the function"
    ),
    "URL_MANIPULATION": (
        "Validate and sanitize user-controlled URL/path input parameters"
    ),
    "LOCALSTORAGE_WRITE": (
        "Avoid storing sensitive data in localStorage; use sessionStorage or "
        "server-side session"
    ),
    "PATH_MANIPULATION": (
        "CWE-22: a user-controlled value is used to build a filesystem path "
        "without sanitization. Find the line that builds the filename from "
        "the unsanitized value (e.g. `filename = f\"{ts}_full_{req.scan_id[:8]}.json\"`) "
        "and apply this exact fix: "
        "1) add `import re` to the top-level imports if not already present; "
        "2) insert a new line right before the filename is built that strips "
        "unsafe characters, e.g. "
        "`safe_scan_id = re.sub(r'[^A-Za-z0-9_-]', '', req.scan_id)[:8]`; "
        "3) use that sanitized variable instead of the raw value in the "
        "f-string, e.g. `filename = f\"{ts}_full_{safe_scan_id}.json\"`."
    ),
}


# ── Models ────────────────────────────────────────────────────────────────────

class FixPrepareRequest(BaseModel):
    scan_id:      str
    auto_submit:  Optional[bool] = False   # True → 自動送給 Bob
    project_root: Optional[str]  = None    # 完整路徑（優先）
    project:      Optional[str]  = None    # 只填名稱，例如 "other-project"


# ── 工具函式 ──────────────────────────────────────────────────────────────────

def _get_report(scan_id: str) -> dict:
    """
    取得掃描報告。
    - scan_id="latest" → 讀取所有報告，依 generated_at 排序，回傳最新的真實掃描（忽略測試資料）
    - 指定 scan_id  → 讀取 JSON 內容比對 scan_id 欄位，確保精確匹配
    """
    all_files = glob.glob(os.path.join(_REPORT_DIR, "*.json"))

    if scan_id == "latest":
        candidates = []
        for f in all_files:
            try:
                with open(f, encoding="utf-8") as fp:
                    data = json.load(fp)
                # 只取真正的掃描報告（scan_id 以 "scan_" 開頭，排除測試資料）
                if str(data.get("scan_id", "")).startswith("scan_"):
                    candidates.append((data.get("generated_at", ""), data))
            except Exception:
                pass
        if candidates:
            # 依 generated_at 排序，取最新一筆
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]
        raise HTTPException(status_code=404, detail="No scan reports found")

    # 指定 scan_id：比對 JSON 內容，確保精確匹配
    for f in all_files:
        try:
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            if data.get("scan_id") == scan_id:
                return data
        except Exception:
            pass

    raise HTTPException(status_code=404, detail=f"Report for scan_id='{scan_id}' not found")


def _find_requirements_files(project_root: str = None) -> list:
    """掃描專案內所有 requirements.txt 路徑（回傳絕對路徑）。"""
    root    = project_root or _PROJECT_ROOT
    pattern = os.path.join(root, "**", "requirements.txt")
    files   = glob.glob(pattern, recursive=True)
    # 回傳絕對路徑，讓 Bob 不論在哪個目錄執行都能找到檔案
    return [os.path.abspath(f) for f in files]


def _filter_high_risk(vulns: list) -> list:
    """過濾 HIGH + CRITICAL，依嚴重程度排序。"""
    filtered = [v for v in vulns if v.get("severity", "").lower() in HIGH_RISK]
    filtered.sort(key=lambda v: SEVERITY_ORDER.get(v.get("severity", "").lower(), 9))
    return filtered


def _group_sca(sca_vulns: list) -> dict:
    """
    將 SCA HIGH/CRITICAL 依套件分組。
    回傳 { "package_name version": { cves, severity, ... } }
    """
    grouped = {}
    for v in sca_vulns:
        comp    = v.get("component", "")
        ver     = v.get("component_ver", "")
        cve     = v.get("cve", "")
        sev     = v.get("severity", "")
        key     = f"{comp} {ver}".strip()
        if not key:
            continue
        if key not in grouped:
            grouped[key] = {
                "package":         comp,
                "current_version": ver,
                "severity":        sev,
                "cves":            [],
                "descriptions":    [],
            }
        if cve and cve not in grouped[key]["cves"]:
            grouped[key]["cves"].append(cve)
        if v.get("description") and v["description"] not in grouped[key]["descriptions"]:
            grouped[key]["descriptions"].append(v["description"])
        # 升級嚴重等級
        if SEVERITY_ORDER.get(sev, 9) < SEVERITY_ORDER.get(grouped[key]["severity"], 9):
            grouped[key]["severity"] = sev
    return grouped


def _group_sast(sast_vulns: list) -> dict:
    """
    將 SAST HIGH/CRITICAL 依 type 分組，並附上受影響的檔案清單。
    """
    grouped = {}
    for v in sast_vulns:
        vtype = v.get("type", "UNKNOWN")
        if vtype not in grouped:
            grouped[vtype] = {
                "type":       vtype,
                "severity":   v.get("severity", ""),
                "cwe":        v.get("cwe", ""),
                "count":      0,
                "files":      [],
                "fix_guide":  SAST_FIX_GUIDE.get(vtype, v.get("remediation", "")),
                "auto_fixable": vtype in SAST_FIX_GUIDE,
            }
        grouped[vtype]["count"] += 1
        entry = {"file": v.get("file", ""), "line": v.get("line")}
        if entry not in grouped[vtype]["files"]:
            grouped[vtype]["files"].append(entry)
    return grouped


def _build_bob_request(project_name: str, sca_grouped: dict,
                        sast_grouped: dict, req_files: list,
                        project_root: str = None) -> dict:
    """
    產生可直接 POST 到 /code-modification/request 的 JSON。
    SCA：套件升級（requirements.txt）
    SAST：程式碼修復（實際原始碼檔案，含行號與修復指引）
    """
    # ── SCA：套件升級 ─────────────────────────────────────────────────────────
    fix_packages = []
    sca_desc_parts = []
    for key, info in sca_grouped.items():
        pkg      = info["package"]
        cves     = ", ".join(info["cves"]) if info["cves"] else "CVE unknown"
        sev      = info["severity"].upper()
        safe_ver = _get_safe_version(pkg)          # 查 PyPI 最新版
        if safe_ver:
            fix_packages.append(f"{pkg}>={safe_ver}")   # e.g. "PyJWT>=2.12.0"
        else:
            fix_packages.append(pkg)               # fallback：只放名稱
        sca_desc_parts.append(
            f"{pkg} {info['current_version']} [{sev}] → 升級至 >={safe_ver or 'latest'} — {cves}"
        )

    # ── SAST：程式碼問題（收集受影響的原始碼檔案） ─────────────────────────────
    sast_fix_items = []     # 結構化，給 build_request_prompt 用
    sast_desc_parts = []
    sast_source_files = []  # 實際原始碼路徑（傳入 affected_files）

    for vtype, info in sast_grouped.items():
        if not info.get("auto_fixable"):
            continue

        # 收集此類型所有受影響檔案
        affected = []
        for fe in info.get("files", []):
            f = fe.get("file", "")
            if f:
                affected.append({"file": f, "line": fe.get("line")})
                if f not in sast_source_files:
                    sast_source_files.append(f)

        sast_fix_items.append({
            "type":      vtype,
            "severity":  info["severity"],
            "cwe":       info.get("cwe", ""),
            "count":     info["count"],
            "fix_guide": info["fix_guide"],
            "files":     affected,
        })
        sast_desc_parts.append(
            f"{vtype} ({info['count']} 處, {info.get('cwe','')}): {info['fix_guide']}"
        )

    # ── 合併描述 ──────────────────────────────────────────────────────────────
    desc_lines = []
    if sca_desc_parts:
        desc_lines.append("=== SCA Dependency Vulnerabilities ===")
        desc_lines.extend(sca_desc_parts)
        desc_lines.append(
            "Action: Upgrade each package to its latest safe version "
            "in all requirements.txt files listed below."
        )
    if sast_desc_parts:
        desc_lines.append("=== SAST Code Issues ===")
        desc_lines.extend(sast_desc_parts)

    # affected_files = requirements.txt（SCA）+ 原始碼（SAST）
    all_affected_files = req_files + sast_source_files

    return {
        "source": "sentinel-flow-fix-filter",
        "type":   "vulnerability_fix",
        "vulnerability_info": {
            "project_name":      project_name or "sentinel-flow-demo",
            "project_root":      os.path.abspath(project_root or _PROJECT_ROOT),  # Bob 執行目錄（絕對路徑）
            "version":           "main",
            "severity":          "HIGH",
            "vulnerability_type": "mixed",
            "affected_files":    all_affected_files,              # 絕對路徑
            "description":       "\n".join(desc_lines),
        },
        "modification_request": {
            "action":       "upgrade_dependency_and_fix_code",
            "details":      "\n".join(desc_lines),
            "fix_packages": fix_packages,       # SCA：套件名稱清單（含版本）
            "sast_fixes":   sast_fix_items,     # SAST：結構化修復指令（含絕對路徑）
            "priority":     "high",
        },
    }


# ── API Endpoints ─────────────────────────────────────────────────────────────

@router.post(
    "/fix/prepare",
    summary="Filter high-risk vulnerabilities and prepare fix plan for Bob",
    operation_id="prepareFix",
)
def prepare_fix(req: FixPrepareRequest):
    """
    從掃描報告中過濾 HIGH / CRITICAL 漏洞，整理成 Bob 可直接讀取的修復計畫 JSON。

    - 支援 scan_id = "latest" 自動取最新報告
    - SCA：依套件分組，列出 CVE 清單
    - SAST：依問題類型分組，附修復指引
    - auto_submit=true：自動送出給 Bob 執行修復
    """
    # 0. 若只傳專案名稱，自動解析路徑
    if req.project and not req.project_root:
        info = resolve_project(req.project)
        if not info["exists"]:
            raise HTTPException(status_code=404,
                detail=f"找不到專案 '{req.project}'，請確認路徑 {info['path']} 存在。")
        req.project_root = info["path"]

    # 1. 取報告
    report  = _get_report(req.scan_id)
    all_sast = report.get("sast_findings", [])
    all_sca  = report.get("sca_findings", [])

    # 2. 過濾高風險
    high_sast = _filter_high_risk(all_sast)
    high_sca  = _filter_high_risk(all_sca)

    # 3. 分組
    sca_grouped  = _group_sca(high_sca)
    sast_grouped = _group_sast(high_sast)

    # 4. 找 requirements.txt 檔案清單（支援其他專案路徑）
    req_files = _find_requirements_files(req.project_root)

    # 5. 產生 Bob 修復指令
    bob_request = _build_bob_request(
        report.get("project_name", "sentinel-flow-demo"),
        sca_grouped, sast_grouped, req_files,
        project_root=req.project_root,
    )

    result = {
        "scan_id":        report.get("scan_id", req.scan_id),
        "project_name":   report.get("project_name"),
        "generated_at":   datetime.now().isoformat(),
        "original_total": len(all_sast) + len(all_sca),
        "high_risk_summary": {
            "total":    len(high_sast) + len(high_sca),
            "sast":     len(high_sast),
            "sca":      len(high_sca),
        },
        "sca_fixes":       list(sca_grouped.values()),
        "sast_fixes":      list(sast_grouped.values()),
        "requirements_files": req_files,
        "bob_request":     bob_request,
        "auto_submitted":  False,
        "submission_result": None,
    }

    # 6. 若 auto_submit，送給 Bob
    if req.auto_submit:
        try:
            r = requests.post(
                CODE_MOD_URL,
                json=bob_request,
                timeout=15,
            )
            result["auto_submitted"]  = True
            result["submission_result"] = r.json()
        except Exception as e:
            result["auto_submitted"]    = False
            result["submission_result"] = {"error": str(e)}

    return result


@router.post(
    "/fix/submit",
    summary="Prepare fix plan and automatically submit to Bob for execution",
    operation_id="submitFix",
)
def submit_fix(req: FixPrepareRequest):
    """
    等同於 /fix/prepare 並強制 auto_submit=true。
    一個指令完成：過濾高風險 → 整理 → 送給 Bob 修復。
    """
    req.auto_submit = True
    return prepare_fix(req)
