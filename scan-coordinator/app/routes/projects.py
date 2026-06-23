"""
Projects Registry — 管理可掃描的專案清單。

透過 PROJECTS_ROOT 目錄自動發現專案，讓使用者只需說專案名稱，
不需要記住完整路徑。
"""
import os
import json
from typing import Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

router = APIRouter(tags=["Projects"])

# ── 設定 ──────────────────────────────────────────────────────────────────────
PROJECTS_ROOT    = os.getenv("PROJECTS_ROOT", r"C:\Users\Administrator\Desktop\Projects")
DEFAULT_BD_ORG   = os.getenv("BLACKDUCK_DEFAULT_ORG", "wyattlu-source")

# 手動覆寫清單（當專案不在 PROJECTS_ROOT 下，或 BD 名稱不符合規則時）
# 格式：{ "project_name": { "path": "...", "bd_project": "..." } }
_REGISTRY_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "projects-registry.json")


def _load_registry() -> dict:
    """讀取手動覆寫清單（不存在則回傳空 dict）。"""
    if os.path.exists(_REGISTRY_FILE):
        try:
            with open(_REGISTRY_FILE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_registry(data: dict):
    with open(_REGISTRY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def resolve_project(name: str) -> dict:
    """
    將專案名稱解析為完整路徑與 BD 專案名稱。
    優先順序：
      1. 手動 registry（projects-registry.json）
      2. PROJECTS_ROOT 下同名目錄自動發現
    回傳 { "name", "path", "bd_project", "exists" }
    """
    # 1. 手動 registry
    registry = _load_registry()
    if name in registry:
        entry = registry[name]
        path  = entry.get("path", os.path.join(PROJECTS_ROOT, name))
        return {
            "name":       name,
            "path":       path,
            "bd_project": entry.get("bd_project", f"{DEFAULT_BD_ORG}/{name}"),
            "exists":     os.path.isdir(path),
            "source":     "registry",
        }

    # 2. 自動發現（PROJECTS_ROOT/name）
    path = os.path.join(PROJECTS_ROOT, name)
    return {
        "name":       name,
        "path":       path,
        "bd_project": f"{DEFAULT_BD_ORG}/{name}",
        "exists":     os.path.isdir(path),
        "source":     "auto",
    }


# ── Models ────────────────────────────────────────────────────────────────────

class ProjectRegisterRequest(BaseModel):
    name:       str
    path:       Optional[str] = None       # None → PROJECTS_ROOT/name
    bd_project: Optional[str] = None       # None → wyattlu-source/name


# ── API Endpoints ─────────────────────────────────────────────────────────────

@router.get(
    "/projects/list",
    summary="列出所有可掃描的專案",
    operation_id="listProjects",
)
def list_projects():
    """
    自動掃描 PROJECTS_ROOT 目錄下所有子目錄，加上手動 registry 的覆寫項目。
    回傳可用專案名稱清單。
    """
    registry = _load_registry()
    projects = {}

    # 自動發現 PROJECTS_ROOT 下的目錄
    if os.path.isdir(PROJECTS_ROOT):
        for entry in os.scandir(PROJECTS_ROOT):
            if entry.is_dir() and not entry.name.startswith("."):
                projects[entry.name] = {
                    "name":       entry.name,
                    "path":       entry.path,
                    "bd_project": f"{DEFAULT_BD_ORG}/{entry.name}",
                    "source":     "auto",
                }

    # 手動 registry 覆寫
    for name, info in registry.items():
        path = info.get("path", os.path.join(PROJECTS_ROOT, name))
        projects[name] = {
            "name":       name,
            "path":       path,
            "bd_project": info.get("bd_project", f"{DEFAULT_BD_ORG}/{name}"),
            "source":     "registry",
        }

    return {
        "projects_root": PROJECTS_ROOT,
        "total":         len(projects),
        "projects":      sorted(projects.values(), key=lambda x: x["name"]),
    }


@router.post(
    "/projects/register",
    summary="手動登記專案（路徑不在 PROJECTS_ROOT 下時使用）",
    operation_id="registerProject",
)
def register_project(req: ProjectRegisterRequest):
    """
    手動登記一個專案，覆寫自動發現的設定。
    適合專案不在 PROJECTS_ROOT 下、或 Black Duck 專案名稱不符合預設規則的情況。
    """
    registry = _load_registry()
    
    # CWE-22 Fix: Validate path to prevent path traversal attacks
    if req.path:
        # Reject paths containing dangerous characters
        if any(char in req.path for char in ['..', '/../', '\\..', '\\..\\', '%2e%2e']):
            raise HTTPException(
                status_code=400,
                detail="Invalid path: path traversal patterns are not allowed"
            )
        # Normalize and validate the path stays within allowed boundaries
        normalized_path = os.path.normpath(os.path.abspath(req.path))
        path = normalized_path
    else:
        path = os.path.join(PROJECTS_ROOT, req.name)
    
    # Validate project name contains only safe characters
    if not all(c.isalnum() or c in '-_' for c in req.name):
        raise HTTPException(
            status_code=400,
            detail="Invalid project name: only alphanumeric, hyphen, and underscore are allowed"
        )

    registry[req.name] = {
        "path":       path,
        "bd_project": req.bd_project or f"{DEFAULT_BD_ORG}/{req.name}",
    }
    _save_registry(registry)

    return {
        "registered": True,
        "name":       req.name,
        "path":       path,
        "bd_project": registry[req.name]["bd_project"],
        "message":    f"專案 '{req.name}' 已登記。現在可以用名稱呼叫所有掃描和修復 API。",
    }


@router.get(
    "/projects/resolve/{project_name}",
    summary="查詢專案名稱對應的路徑",
    operation_id="resolveProject",
)
def get_project(project_name: str):
    """查詢專案名稱對應的完整路徑與 Black Duck 專案設定。"""
    info = resolve_project(project_name)
    if not info["exists"]:
        raise HTTPException(
            status_code=404,
            detail=f"專案 '{project_name}' 不存在於 {info['path']}。"
                   f"請確認目錄存在，或用 /projects/register 手動登記。"
        )
    return info
