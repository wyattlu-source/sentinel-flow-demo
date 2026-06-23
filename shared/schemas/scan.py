from pydantic import BaseModel
from typing import List, Optional
from .vulnerability import VulnerabilityItem, ScanType


class ScanRequest(BaseModel):
    project_name: str
    repo_url: Optional[str] = None
    target_url: Optional[str] = None
    scan_types: List[ScanType] = [ScanType.SAST, ScanType.DAST, ScanType.SCA]


class ScanJob(BaseModel):
    scan_id: str
    project_name: str
    status: str  # pending | running | completed | failed
    started_at: str
    completed_at: Optional[str] = None
    sast_status: str = "pending"
    dast_status: str = "pending"
    sca_status: str = "pending"


class ScanResult(BaseModel):
    scan_id: str
    scan_type: ScanType
    phase: str  # before_fix | after_fix
    scanned_at: str
    vulnerabilities: List[VulnerabilityItem] = []
