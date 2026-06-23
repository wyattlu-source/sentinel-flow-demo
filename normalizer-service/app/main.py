"""
Normalizer Service — 將 SAST / SCA 原始結果轉換為統一的 VulnerabilityItem 格式。

統一格式（VulnerabilityItem）：
  source       : sast | sca
  severity     : critical | high | medium | low | audit
  type         : checker 名稱 或 CVE ID
  title        : 簡短說明
  file         : 相對路徑（SAST）
  line         : 行號（SAST）
  function     : function 名稱（SAST）
  cwe          : CWE-xxx（SAST）
  component    : 套件名稱（SCA）
  component_ver: 套件版本（SCA）
  cve          : CVE ID（SCA）
  remediation  : 修復建議
"""

import json
import os
from datetime import datetime
from typing import Any, Optional

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

BD_URL      = os.getenv("BLACKDUCK_SERVICE_URL", "http://localhost:8006")
BD_PROJECT  = os.getenv("BLACKDUCK_DEFAULT_PROJECT", "wyattlu-source/sentinel-flow-demo")
BD_VERSION  = os.getenv("BLACKDUCK_DEFAULT_VERSION", "main")

app = FastAPI(
    title="Normalizer Service",
    description="將 SAST / SCA 原始結果統一轉換為 VulnerabilityItem 格式。",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── 嚴重程度對照表 ────────────────────────────────────────────────────────────

_SAST_SEVERITY = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "audit":    "audit",
    "":         "medium",
}

_SCA_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
}


# ── Models ────────────────────────────────────────────────────────────────────

class SastNormRequest(BaseModel):
    """SAST status endpoint 回傳的原始資料（含 report_path）。"""
    status:      Optional[str] = None
    total:       Optional[int] = 0
    checkers:    Optional[list] = []
    report_path: Optional[str] = None


class ScaNormRequest(BaseModel):
    project: Optional[str] = None
    version: Optional[str] = None


# ── SAST Parser ───────────────────────────────────────────────────────────────

def _parse_sast_full(report_path: str) -> list:
    """從 Coverity JSON 報告解析完整漏洞清單。"""
    vulns = []
    try:
        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        for issue in data.get("issues", []):
            props    = issue.get("checkerProperties", {})
            impact   = props.get("impact", "").lower()
            severity = _SAST_SEVERITY.get(impact, "medium")
            cwe_raw  = props.get("cweCategory", "")
            cwe      = f"CWE-{cwe_raw}" if cwe_raw else ""

            # 從 events 取主要事件描述
            events   = issue.get("events", [])
            main_evt = next((e for e in events if e.get("main")), {})
            evt_desc = main_evt.get("eventDescription", "")

            vulns.append({
                "source":        "sast",
                "severity":      severity,
                "type":          issue.get("checkerName", "UNKNOWN"),
                "title":         props.get("subcategoryShortDescription") or issue.get("checkerName", ""),
                "description":   evt_desc,
                "file":          issue.get("strippedMainEventFilePathname", ""),
                "line":          issue.get("mainEventLineNumber", 0),
                "column":        issue.get("mainEventColumnNumber", 0),
                "function":      issue.get("functionDisplayName", ""),
                "cwe":           cwe,
                "language":      issue.get("language", ""),
                "remediation":   props.get("subcategoryLongDescription", ""),
            })
    except Exception:
        pass
    return vulns


def _parse_sast_summary(checkers: list) -> list:
    """從摘要（checker + count）產生簡化漏洞清單（無完整 report 時的 fallback）。"""
    vulns = []
    for item in checkers:
        checker = item.get("checker", "UNKNOWN")
        count   = item.get("count", 1)
        for _ in range(count):
            vulns.append({
                "source":   "sast",
                "severity": "medium",
                "type":     checker,
                "title":    checker,
            })
    return vulns


# ── SCA Parser ────────────────────────────────────────────────────────────────

def _parse_sca(project: str, version: str) -> list:
    """從 BlackDuck service 取得漏洞清單並正規化。
    blackduck-service 回傳的是 VulnerableComponent 格式（snake_case）：
      component_name, component_version, vulnerability_name,
      severity, cvss_score, description, published_date, remediation_status
    """
    vulns = []
    try:
        url = f"{BD_URL}/blackduck/projects/{project}/vulnerabilities"
        r = requests.get(url, params={"version": version}, timeout=30)
        if not r.ok:
            return vulns

        for item in r.json():
            component_name = item.get("component_name", "")
            component_ver  = item.get("component_version", "")
            vuln_name      = item.get("vulnerability_name", "")
            severity_raw   = item.get("severity", "LOW")
            description    = item.get("description", "")
            remediation    = item.get("remediation_status", "")
            cvss           = item.get("cvss_score")

            severity = _SCA_SEVERITY.get(severity_raw.upper(), "low")

            # 組合 title：套件名 版本 (CVE-XXXX)
            parts = []
            if component_name:
                parts.append(component_name)
            if component_ver:
                parts.append(component_ver)
            title = " ".join(parts)
            if vuln_name:
                title = f"{title} ({vuln_name})" if title else vuln_name

            vulns.append({
                "source":        "sca",
                "severity":      severity,
                "type":          vuln_name or "UNKNOWN",
                "title":         title,
                "description":   description,
                "component":     component_name,
                "component_ver": component_ver,
                "cve":           vuln_name,
                "cvss_score":    cvss,
                "remediation":   remediation,
            })
    except Exception as e:
        print(f"[SCA normalize error] {e}")
    return vulns


# ── API Endpoints ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "normalizer-service", "port": 8014, "version": "1.0.0"}


@app.post("/normalize/sast", summary="正規化 SAST 結果")
def normalize_sast(req: SastNormRequest):
    """
    接收 SAST status 回傳資料。
    若有 report_path 則解析完整 Coverity JSON；否則用摘要資料。
    """
    report_path = req.report_path or ""

    if report_path and os.path.exists(report_path):
        vulns = _parse_sast_full(report_path)
        source = "full_report"
    else:
        vulns = _parse_sast_summary(req.checkers or [])
        source = "summary_fallback"

    return {
        "scan_type":       "sast",
        "normalized_at":   datetime.now().isoformat(),
        "source":          source,
        "total":           len(vulns),
        "vulnerabilities": vulns,
    }


@app.post("/normalize/sca", summary="正規化 SCA 結果")
def normalize_sca(req: ScaNormRequest):
    """
    從 BlackDuck service 取得漏洞清單並正規化。
    """
    project = req.project or BD_PROJECT
    version = req.version or BD_VERSION
    vulns   = _parse_sca(project, version)

    return {
        "scan_type":       "sca",
        "normalized_at":   datetime.now().isoformat(),
        "project":         project,
        "version":         version,
        "total":           len(vulns),
        "vulnerabilities": vulns,
    }
