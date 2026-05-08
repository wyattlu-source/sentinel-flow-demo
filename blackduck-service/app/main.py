from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from dotenv import load_dotenv, find_dotenv
from .blackduck_client import BlackDuckClient

load_dotenv(find_dotenv())

app = FastAPI(
    title="BlackDuck Service",
    description="Black Duck SCA API bridge for watsonx Orchestrate integration. "
                "Provides vulnerability summaries, component BOM, and risk data from Black Duck.",
    version="1.0.0",
)

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
    "/blackduck/projects/{project_name}/summary",
    response_model=VulnerabilitySummary,
    tags=["Black Duck"],
    summary="Get vulnerability summary",
    operation_id="getVulnerabilitySummary",
)
def get_summary(
    project_name: str,
    version: str = Query(default="main", description="Project version name"),
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
    "/blackduck/projects/{project_name}/vulnerabilities",
    response_model=List[VulnerableComponent],
    tags=["Black Duck"],
    summary="List vulnerable components",
    operation_id="listVulnerabilities",
)
def list_vulnerabilities(
    project_name: str,
    version: str = Query(default="main", description="Project version name"),
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
    "/blackduck/projects/{project_name}/components",
    response_model=List[ComponentItem],
    tags=["Black Duck"],
    summary="List all BOM components",
    operation_id="listComponents",
)
def list_components(
    project_name: str,
    version: str = Query(default="main", description="Project version name"),
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
