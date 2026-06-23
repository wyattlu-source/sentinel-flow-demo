"""
Code Modification Request Handler
Handles requests from orchestrate to modify code for vulnerability fixes.
"""

import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from fastapi import HTTPException, Query
import uuid
import os

# Get project root directory
_SERVICE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVICE_DIR)
CODE_REQUESTS_DIR = Path(_PROJECT_DIR) / ".code-requests"


# ── Models ────────────────────────────────────────────────────────────────────

class VulnerabilityInfo(BaseModel):
    project_name: str
    version: str
    severity: str
    vulnerability_type: str
    affected_files: List[str]
    description: str


class ModificationRequest(BaseModel):
    action: str
    details: str = Field(
        description=(
            "Human-readable fix description. "
            "MUST include each package version in 'package>=version' format, e.g.: "
            "'urllib3>=2.6.3; PyJWT>=2.12.0; lxml>=6.1.0'. "
            "Black Duck reads the minimum version number in requirements.txt, so the "
            "number itself must be changed (>=2.3.0 is still treated as 2.3.0)."
        )
    )
    fix_packages: Optional[List[str]] = Field(
        default=None,
        description=(
            "Structured list of packages to upgrade. Each entry MUST be in "
            "'package>=version' format, e.g. ['urllib3>=2.6.3', 'PyJWT>=2.12.0']. "
            "When provided, this takes precedence over parsing the details field. "
            "Use this for precise, unambiguous version pinning."
        ),
        examples=[["urllib3>=2.6.3", "PyJWT>=2.12.0", "lxml>=6.1.0"]],
    )
    priority: str = "medium"


class CodeModificationRequest(BaseModel):
    source: str = "orchestrate"
    type: str = "vulnerability_fix"
    vulnerability_info: VulnerabilityInfo
    modification_request: ModificationRequest


class CodeModificationResponse(BaseModel):
    request_id: str
    status: str
    timestamp: str
    message: str


# ── Helper Functions ──────────────────────────────────────────────────────────

def _save_code_request(request_id: str, request_data: dict, status: str = "pending"):
    """Save code modification request to JSON file"""
    request_file = CODE_REQUESTS_DIR / status / f"{request_id}.json"
    request_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(request_file, 'w', encoding='utf-8') as f:
        json.dump(request_data, f, indent=2, ensure_ascii=False)
    
    return request_file


def _move_request(request_id: str, from_status: str, to_status: str):
    """Move request file between status directories"""
    from_file = CODE_REQUESTS_DIR / from_status / f"{request_id}.json"
    to_file = CODE_REQUESTS_DIR / to_status / f"{request_id}.json"
    
    if from_file.exists():
        to_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(from_file), str(to_file))
        return True
    return False


def _get_request(request_id: str):
    """Get request from any status directory"""
    for status in ["pending", "processing", "completed", "failed"]:
        request_file = CODE_REQUESTS_DIR / status / f"{request_id}.json"
        if request_file.exists():
            with open(request_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                data["status"] = status
                return data
    return None


# ── API Handlers ──────────────────────────────────────────────────────────────

def create_code_modification_request(request: CodeModificationRequest):
    """
    Submit a code modification request to fix vulnerabilities.
    The request will be saved and automatically processed by the configured AI CLI (Bob or Claude Code).

    Workflow:
    1. Orchestrate sends modification request
    2. Request is saved to .code-requests/pending/
    3. claude_auto_fix.py detects it and calls the configured CLI automatically
    4. AI reads the affected files and applies the fix
    5. Status updated to completed
    """
    try:
        request_id = f"req_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        timestamp = datetime.now().isoformat()
        
        request_data = {
            "request_id": request_id,
            "timestamp": timestamp,
            "source": request.source,
            "type": request.type,
            "status": "pending",
            "vulnerability_info": request.vulnerability_info.dict(),
            "modification_request": request.modification_request.dict(),
            "result": None,
            "completed_at": None,
        }
        
        _save_code_request(request_id, request_data, "pending")
        
        return CodeModificationResponse(
            request_id=request_id,
            status="pending",
            timestamp=timestamp,
            message=f"Code modification request created. Request ID: {request_id}. "
                   f"File saved to: .code-requests/pending/{request_id}.json. "
                   f"{os.getenv('AUTO_FIX_CLI', 'claude').upper()} CLI (claude_auto_fix.py) will process this automatically."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create request: {str(e)}")


def get_code_modification_status(request_id: str):
    """
    Check the status of a code modification request.
    Status can be: pending, processing, completed, or failed.
    """
    request_data = _get_request(request_id)
    if not request_data:
        raise HTTPException(status_code=404, detail=f"Request '{request_id}' not found")
    
    return request_data


def list_code_modification_requests(status: Optional[str] = None):
    """
    List all code modification requests, optionally filtered by status.
    """
    try:
        requests = []
        statuses = [status] if status else ["pending", "processing", "completed", "failed"]
        
        for s in statuses:
            status_dir = CODE_REQUESTS_DIR / s
            if status_dir.exists():
                for request_file in status_dir.glob("*.json"):
                    with open(request_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        data["status"] = s
                        requests.append(data)
        
        # Sort by timestamp, newest first
        requests.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return {"total": len(requests), "requests": requests}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list requests: {str(e)}")


def update_code_modification_status(
    request_id: str,
    new_status: str,
    result: Optional[str] = None
):
    """
    Update the status of a code modification request.
    Updated automatically by Claude Code CLI after processing the request.
    """
    if new_status not in ["processing", "completed", "failed"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Must be: processing, completed, or failed"
        )
    
    request_data = _get_request(request_id)
    if not request_data:
        raise HTTPException(status_code=404, detail=f"Request '{request_id}' not found")
    
    current_status = request_data["status"]
    
    # Update request data
    request_data["status"] = new_status
    if result:
        request_data["result"] = result
    if new_status in ["completed", "failed"]:
        request_data["completed_at"] = datetime.now().isoformat()
    
    # Move file to new status directory
    _move_request(request_id, current_status, new_status)
    
    # Save updated data
    _save_code_request(request_id, request_data, new_status)
    
    return {
        "request_id": request_id,
        "old_status": current_status,
        "new_status": new_status,
        "message": f"Status updated from '{current_status}' to '{new_status}'"
    }

