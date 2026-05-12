from fastapi import FastAPI, HTTPException, Query, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel
from typing import List, Optional
import os
import uuid
import subprocess
import threading
from datetime import datetime
from dotenv import load_dotenv, find_dotenv
from .blackduck_client import BlackDuckClient
from . import orchestrate_client
from . import code_modification
from . import analysis_collector

load_dotenv(find_dotenv())

DEFAULT_PROJECT = os.getenv("BLACKDUCK_DEFAULT_PROJECT", "wyattlu-source/sentinel-flow-demo")
DEFAULT_VERSION = os.getenv("BLACKDUCK_DEFAULT_VERSION", "main")

# blackduck-service/ dir and project root, resolved from this file's location
_SERVICE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVICE_DIR)

_raw_detect_dir = os.getenv("DETECT_SCRIPT_DIR", "")
_raw_source_path = os.getenv("DETECT_SOURCE_PATH", "")
DETECT_SCRIPT_DIR = _raw_detect_dir if os.path.isabs(_raw_detect_dir) else _SERVICE_DIR
DETECT_SOURCE_PATH = _raw_source_path if os.path.isabs(_raw_source_path) else _PROJECT_DIR

_scan_jobs: dict = {}

app = FastAPI(
    title="BlackDuck Service",
    description="Black Duck SCA API bridge for watsonx Orchestrate integration. "
                "Provides vulnerability summaries, component BOM, and risk data from Black Duck.",
    version="1.0.0",
)

NL_INTENTS = {
    "triggerScan": [
        "start a Black Duck scan",
        "scan the project for vulnerabilities",
        "run Black Duck scan",
        "trigger security scan",
        "幫我掃描專案",
        "啟動 Black Duck 掃描",
        "執行漏洞掃描",
    ],
    "getScanStatus": [
        "check scan status",
        "is the scan done",
        "scan progress",
        "掃描狀態",
        "掃描完成了嗎",
    ],
    "listProjects": [
        "list all Black Duck projects",
        "show me all projects in Black Duck",
        "what projects are being scanned",
    ],
    "getVulnerabilitySummary": [
        "show vulnerability summary",
        "how many vulnerabilities does this project have",
        "give me a security risk summary",
        "what is the vulnerability count",
    ],
    "listVulnerabilities": [
        "list all vulnerabilities",
        "show high severity vulnerabilities",
        "what CVEs are in this project",
        "show me the security issues",
        "list critical vulnerabilities",
    ],
    "listComponents": [
        "show all components",
        "list the bill of materials",
        "what open source libraries are used",
        "show BOM components",
    ],
    "requestCodeModification": [
        "fix the vulnerability in my code",
        "修復程式碼中的漏洞",
        "幫我改程式",
        "自動修復安全問題",
        "請修改程式碼來解決漏洞",
        "fix security issues automatically",
        "modify code to fix vulnerabilities",
    ],
    "getCodeModificationStatus": [
        "check code modification status",
        "查詢程式碼修改狀態",
        "修改完成了嗎",
        "is the code fix done",
    ],
    "listCodeModificationRequests": [
        "list all code modification requests",
        "列出所有程式碼修改請求",
        "show pending code fixes",
        "顯示待處理的修改",
    ],
    "collectAnalysisMessage": [
        "send analysis result to be auto-fixed",
        "submit vulnerability analysis for automatic fix",
        "送出分析結果讓 Claude 自動修復",
        "把漏洞分析送給自動修復系統",
        "auto fix this vulnerability",
        "自動修復這個漏洞",
    ],
    "listAnalysisMessages": [
        "list analysis messages",
        "show submitted analysis results",
        "查看分析訊息",
        "列出已送出的分析",
    ],
    "getUnprocessedMessages": [
        "show unprocessed messages",
        "what is pending auto-fix",
        "有哪些訊息尚未處理",
        "查看待修復的問題",
    ],
}


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    schema["openapi"] = "3.0.3"
    server_url = os.getenv("BLACKDUCK_SERVICE_URL", "http://localhost:8006")
    schema["servers"] = [{"url": server_url, "description": "BlackDuck Service"}]

    for path_item in schema.get("paths", {}).values():
        for operation in path_item.values():
            op_id = operation.get("operationId", "")
            if op_id in NL_INTENTS:
                operation["x-ibm-nl-intent-examples"] = NL_INTENTS[op_id]
            for param in operation.get("parameters", []):
                if param.get("name") == "project_name":
                    param["schema"]["default"] = DEFAULT_PROJECT
                    param["description"] = f"Black Duck project name (default: {DEFAULT_PROJECT})"
                if param.get("name") == "version":
                    param["schema"]["default"] = DEFAULT_VERSION

    app.openapi_schema = schema
    return app.openapi_schema


app.openapi = custom_openapi

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = BlackDuckClient()


# ── Response Models ───────────────────────────────────────────────────────────

class ProjectInfo(BaseModel):
    name: str
    description: Optional[str] = None
    href: str


class VulnerabilitySummary(BaseModel):
    project_name: str
    version: str
    critical: int
    high: int
    medium: int
    low: int
    total_components: int
    vulnerable_components: int


class VulnerableComponent(BaseModel):
    component_name: str
    component_version: Optional[str] = None
    vulnerability_name: str
    severity: str
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    published_date: Optional[str] = None
    remediation_status: Optional[str] = None


class ComponentItem(BaseModel):
    name: str
    version: Optional[str] = None
    license: Optional[str] = None
    usage: Optional[str] = None
    security_risk: Optional[str] = None
    license_risk: Optional[str] = None


# ── Helper ────────────────────────────────────────────────────────────────────

def _resolve_version(project_name: str, version: str):
    project = client.find_project(project_name)
    if not project:
        raise HTTPException(status_code=404, detail=f"Project '{project_name}' not found")
    project_href = project["_meta"]["href"]
    ver = client.find_version(project_href, version)
    if not ver:
        raise HTTPException(status_code=404, detail=f"Version '{version}' not found")
    return project, ver


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health():
    """Health check for blackduck-service."""
    return {"status": "ok", "service": "blackduck-service", "port": 8006}


@app.get(
    "/blackduck/projects",
    response_model=List[ProjectInfo],
    tags=["Black Duck"],
    summary="List all Black Duck projects",
    operation_id="listProjects",
)
def list_projects():
    """Return all projects registered in Black Duck SCA."""
    try:
        items = client.list_projects()
        return [
            ProjectInfo(
                name=p.get("name", ""),
                description=p.get("description"),
                href=p.get("_meta", {}).get("href", ""),
            )
            for p in items
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/blackduck/projects/{project_name:path}/summary",
    response_model=VulnerabilitySummary,
    tags=["Black Duck"],
    summary="Get vulnerability summary",
    operation_id="getVulnerabilitySummary",
)
def get_summary(
    project_name: str = DEFAULT_PROJECT,
    version: str = Query(default=DEFAULT_VERSION, description="Project version name"),
):
    """
    Get vulnerability counts (Critical / High / Medium / Low) for a project version.
    Useful for dashboard reporting and risk assessment.
    """
    try:
        _, ver = _resolve_version(project_name, version)
        version_href = ver["_meta"]["href"]

        components = client.list_components(version_href)
        vulnerable = client.list_vulnerable_components(version_href)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in vulnerable:
            vwr = item.get("vulnerabilityWithRemediation", {})
            sev = vwr.get("severity", "").upper()
            if sev in counts:
                counts[sev] += 1

        return VulnerabilitySummary(
            project_name=project_name,
            version=ver.get("versionName", version),
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            low=counts["LOW"],
            total_components=len(components),
            vulnerable_components=len(vulnerable),
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/blackduck/projects/{project_name:path}/vulnerabilities",
    response_model=List[VulnerableComponent],
    tags=["Black Duck"],
    summary="List vulnerable components",
    operation_id="listVulnerabilities",
)
def list_vulnerabilities(
    project_name: str = DEFAULT_PROJECT,
    version: str = Query(default=DEFAULT_VERSION, description="Project version name"),
    severity: Optional[str] = Query(default=None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
):
    """
    List all components with known CVE vulnerabilities.
    Optionally filter by severity level.
    """
    try:
        _, ver = _resolve_version(project_name, version)
        version_href = ver["_meta"]["href"]
        items = client.list_vulnerable_components(version_href)

        result = []
        for item in items:
            vwr = item.get("vulnerabilityWithRemediation", {})
            sev = vwr.get("severity", "").upper()
            if severity and sev != severity.upper():
                continue
            result.append(VulnerableComponent(
                component_name=item.get("componentName", ""),
                component_version=item.get("componentVersionName"),
                vulnerability_name=vwr.get("vulnerabilityName", ""),
                severity=sev,
                cvss_score=vwr.get("baseScore"),
                description=vwr.get("description"),
                published_date=vwr.get("publishedDate"),
                remediation_status=vwr.get("remediationStatus"),
            ))

        result.sort(key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.severity)
                    if x.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else 99)
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get(
    "/blackduck/projects/{project_name:path}/components",
    response_model=List[ComponentItem],
    tags=["Black Duck"],
    summary="List all BOM components",
    operation_id="listComponents",
)
def list_components(
    project_name: str = DEFAULT_PROJECT,
    version: str = Query(default=DEFAULT_VERSION, description="Project version name"),
):
    """
    Return the full Bill of Materials (BOM) for a project version,
    including license and security risk information.
    """
    try:
        _, ver = _resolve_version(project_name, version)
        version_href = ver["_meta"]["href"]
        items = client.list_components(version_href)

        result = []
        for item in items:
            licenses = item.get("licenses", [])
            license_name = licenses[0].get("licenseDisplay") if licenses else None
            risk = item.get("securityRiskProfile", {}).get("counts", [])
            sec_risk = next(
                (r["countType"] for r in risk if r.get("count", 0) > 0),
                "NONE"
            )
            result.append(ComponentItem(
                name=item.get("componentName", ""),
                version=item.get("componentVersionName"),
                license=license_name,
                usage=item.get("usages", [None])[0],
                security_risk=sec_risk,
                license_risk=item.get("licenseRiskProfile", {})
                              .get("counts", [{}])[0].get("countType"),
            ))
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Scan Trigger ──────────────────────────────────────────────────────────────

class ScanJob(BaseModel):
    job_id: str
    status: str
    started_at: str
    source_path: str


def _run_detect(job_id: str, source_path: str):
    blackduck_url = os.getenv("BLACKDUCK_URL", "")
    api_token = os.getenv("BLACKDUCK_API_TOKEN", "")
    ps_cmd = (
        f"Set-Location '{DETECT_SCRIPT_DIR}'; "
        f". .\\detect11.ps1; "
        f"Detect "
        f"'--blackduck.url={blackduck_url}' "
        f"'--blackduck.api.token={api_token}' "
        f"'--blackduck.trust.cert=true' "
        f"'--detect.source.path={source_path}'"
    )
    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=900,
        )
        if result.returncode == 0:
            _scan_jobs[job_id]["status"] = "completed"
        else:
            _scan_jobs[job_id]["status"] = "failed"
            _scan_jobs[job_id]["error"] = result.stderr[-1000:] if result.stderr else ""
    except subprocess.TimeoutExpired:
        _scan_jobs[job_id]["status"] = "timeout"
    except Exception as e:
        _scan_jobs[job_id]["status"] = "failed"
        _scan_jobs[job_id]["error"] = str(e)


@app.post(
    "/blackduck/scan/trigger",
    response_model=ScanJob,
    tags=["Scan"],
    summary="Trigger a Black Duck scan",
    operation_id="triggerScan",
)
def trigger_scan(
    source_path: str = Query(default=DETECT_SOURCE_PATH, description="Path to source code to scan"),
):
    """
    Trigger a Synopsys Detect scan on the specified source path.
    Returns a job_id to track progress. Scan runs in the background.
    """
    job_id = uuid.uuid4().hex[:8]
    started_at = datetime.now().isoformat()
    _scan_jobs[job_id] = {"status": "running", "started_at": started_at, "source_path": source_path}
    threading.Thread(target=_run_detect, args=(job_id, source_path), daemon=True).start()
    return ScanJob(job_id=job_id, status="running", started_at=started_at, source_path=source_path)


@app.get(
    "/blackduck/scan/status/{job_id}",
    tags=["Scan"],
    summary="Get scan job status",
    operation_id="getScanStatus",
)
def get_scan_status(job_id: str):
    """Check the status of a triggered scan job."""
    job = _scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return {"job_id": job_id, **job}


# ── Webhook ───────────────────────────────────────────────────────────────────

@app.post(
    "/webhook/scan-complete",
    tags=["Webhook"],
    summary="Receive Black Duck scan completion webhook",
)
async def webhook_scan_complete(request: Request):
    """
    Endpoint for Black Duck to POST when a scan (BOM computation) completes.
    Automatically fetches vulnerability data and notifies watsonx Orchestrate.
    Configure in Black Duck: Notifications > Add Webhook > Event: BOM_COMPUTED.
    """
    try:
        payload = await request.json()
    except Exception:
        payload = {}

    content = payload.get("content", {})
    project_name = content.get("projectName", DEFAULT_PROJECT)
    version_name = content.get("projectVersionName", DEFAULT_VERSION)

    try:
        _, ver = _resolve_version(project_name, version_name)
        version_href = ver["_meta"]["href"]
        components = client.list_components(version_href)
        vulnerable = client.list_vulnerable_components(version_href)

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in vulnerable:
            sev = item.get("vulnerabilityWithRemediation", {}).get("severity", "").upper()
            if sev in counts:
                counts[sev] += 1

        summary = {
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "total_components": len(components),
            "vulnerable_components": len(vulnerable),
        }

        try:
            orchestrate_client.notify_scan_complete(project_name, version_name, summary)
            notify_status = "sent"
        except Exception as e:
            notify_status = f"failed: {e}"

        return {
            "status": "processed",
            "project": project_name,
            "version": version_name,
            "summary": summary,
            "orchestrate_notification": notify_status,
        }
    except HTTPException as e:
        return {"status": "error", "detail": e.detail}


# ── Code Modification Endpoints ───────────────────────────────────────────────

@app.post(
    "/code-modification/request",
    response_model=code_modification.CodeModificationResponse,
    tags=["Code Modification"],
    summary="Request code modification for vulnerability fix",
    operation_id="requestCodeModification",
)
def request_code_modification(request: code_modification.CodeModificationRequest):
    """
    Submit a code modification request to fix a vulnerability.
    The request is saved to .code-requests/pending/ and automatically
    processed by Claude Code CLI (claude_auto_fix.py).

    Workflow:
    1. Orchestrate sends modification request here
    2. Request saved to .code-requests/pending/
    3. claude_auto_fix.py detects it and calls `claude -p` automatically
    4. Claude reads the affected files and applies the fix
    5. Status updated to completed
    """
    return code_modification.create_code_modification_request(request)


@app.get(
    "/code-modification/status/{request_id}",
    tags=["Code Modification"],
    summary="Get code modification request status",
    operation_id="getCodeModificationStatus",
)
def get_code_modification_status(request_id: str):
    """
    Check the status of a code modification request.
    Status: pending → (auto-processed by Claude CLI) → completed / failed.
    """
    return code_modification.get_code_modification_status(request_id)


@app.get(
    "/code-modification/list",
    tags=["Code Modification"],
    summary="List all code modification requests",
    operation_id="listCodeModificationRequests",
)
def list_code_modification_requests(
    status: Optional[str] = Query(default=None, description="Filter by status: pending, processing, completed, failed")
):
    """List all code modification requests, optionally filtered by status."""
    return code_modification.list_code_modification_requests(status)


# ── Analysis Message Endpoints ────────────────────────────────────────────────

@app.post(
    "/analysis/collect",
    response_model=analysis_collector.AnalysisResponse,
    tags=["Analysis"],
    summary="Submit vulnerability analysis for automatic code fix",
    operation_id="collectAnalysisMessage",
)
def collect_analysis_message(message: analysis_collector.AnalysisMessage):
    """
    Orchestrate sends vulnerability analysis results here.
    Messages are saved to .analysis-messages/ and automatically processed
    by Claude Code CLI (claude_auto_fix.py).

    Workflow:
    1. Orchestrate analyses scan results and sends findings here
    2. Message saved to .analysis-messages/
    3. claude_auto_fix.py calls `claude -p` automatically
    4. Claude reads the message, finds affected files, applies fixes
    """
    return analysis_collector.collect_analysis_message(message)


@app.get(
    "/analysis/messages",
    tags=["Analysis"],
    summary="List analysis messages",
    operation_id="listAnalysisMessages",
)
def list_analysis_messages(
    processed: Optional[bool] = Query(default=None, description="Filter: true=processed, false=pending, omit=all")
):
    """List submitted analysis messages, optionally filtered by processed status."""
    return analysis_collector.list_analysis_messages(processed)


@app.get(
    "/analysis/unprocessed",
    tags=["Analysis"],
    summary="Get unprocessed analysis messages",
    operation_id="getUnprocessedMessages",
)
def get_unprocessed_messages():
    """Return all messages not yet processed by Claude Code CLI."""
    return analysis_collector.get_unprocessed_messages()
