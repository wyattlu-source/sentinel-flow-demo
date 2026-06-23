"""
Git 整合 — commit 修改並建立 Pull Request。
TODO: 實作
"""
import subprocess
from pathlib import Path


def commit_and_pr(repo_path: str, branch: str, message: str, files: list[str]) -> dict:
    """
    修復完成後自動 commit + 建立 PR。

    TODO:
    - git checkout -b fix/<scan_id>
    - git add <affected_files>
    - git commit -m <message>
    - git push origin <branch>
    - 呼叫 GitHub / GitLab API 建立 PR
    """
    return {
        "status": "stub",
        "note": "git commit / PR 功能尚未實作",
        "repo_path": repo_path,
        "branch": branch,
        "message": message,
    }
