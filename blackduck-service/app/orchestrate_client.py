import os
import requests
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

IAM_TOKEN_URL = "https://iam.cloud.ibm.com/identity/token"


def _get_iam_token(api_key: str) -> str:
    resp = requests.post(
        IAM_TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "urn:ibm:params:oauth:grant-type:apikey",
            "apikey": api_key,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def notify_scan_complete(project_name: str, version: str, summary: dict) -> dict:
    """Send scan completion notification to watsonx Orchestrate chat API."""
    api_key = os.getenv("WATSONX_API_KEY", "")
    instance_url = os.getenv("WATSONX_URL", "").rstrip("/")

    if not api_key or not instance_url:
        raise RuntimeError("WATSONX_API_KEY or WATSONX_URL not configured")

    token = _get_iam_token(api_key)

    vuln_lines = []
    if summary.get("critical", 0):
        vuln_lines.append(f"- Critical: {summary['critical']}")
    if summary.get("high", 0):
        vuln_lines.append(f"- High: {summary['high']}")
    if summary.get("medium", 0):
        vuln_lines.append(f"- Medium: {summary['medium']}")
    if summary.get("low", 0):
        vuln_lines.append(f"- Low: {summary['low']}")

    message = (
        f"Black Duck 掃描完成。專案：{project_name}（版本：{version}）\n\n"
        f"漏洞摘要：\n" + "\n".join(vuln_lines or ["- 無漏洞"]) + "\n\n"
        f"受影響元件數：{summary.get('vulnerable_components', 0)} / "
        f"{summary.get('total_components', 0)}\n\n"
        f"請分析以上漏洞，列出高風險項目並提供修復建議。"
    )

    resp = requests.post(
        f"{instance_url}/v1/chat",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json={"input": message},
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()
