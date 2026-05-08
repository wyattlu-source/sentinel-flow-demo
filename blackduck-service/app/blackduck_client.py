import os
import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())


class BlackDuckClient:
    def __init__(self):
        self.base_url = os.getenv("BLACKDUCK_URL", "").rstrip("/")
        self.api_token = os.getenv("BLACKDUCK_API_TOKEN", "")
        self.verify_ssl = os.getenv("BLACKDUCK_TRUST_CERT", "true").lower() != "true"
        self._bearer_token = None
        self._token_expires_at = datetime.min

    def _authenticate(self):
        resp = requests.post(
            f"{self.base_url}/api/tokens/authenticate",
            headers={"Authorization": f"token {self.api_token}"},
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._bearer_token = data["bearerToken"]
        expires_ms = data.get("expiresInMilliseconds", 3600000)
        self._token_expires_at = datetime.now() + timedelta(milliseconds=expires_ms - 60000)

    def _token(self):
        if not self._bearer_token or datetime.now() >= self._token_expires_at:
            self._authenticate()
        return self._bearer_token

    def _get(self, url, accept="application/json", params=None):
        if not url.startswith("http"):
            url = f"{self.base_url}{url}"
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self._token()}", "Accept": accept},
            params=params,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Projects ──────────────────────────────────────────────────────────────

    def list_projects(self):
        data = self._get(
            "/api/projects",
            "application/vnd.blackducksoftware.project-detail-4+json",
            params={"limit": 100},
        )
        return data.get("items", [])

    def find_project(self, name: str):
        data = self._get(
            "/api/projects",
            "application/vnd.blackducksoftware.project-detail-4+json",
            params={"q": f"name:{name}", "limit": 10},
        )
        items = data.get("items", [])
        for item in items:
            if item.get("name", "").lower() == name.lower():
                return item
        return items[0] if items else None

    # ── Versions ──────────────────────────────────────────────────────────────

    def list_versions(self, project_href: str):
        data = self._get(
            f"{project_href}/versions",
            "application/vnd.blackducksoftware.project-detail-5+json",
            params={"limit": 20},
        )
        return data.get("items", [])

    def find_version(self, project_href: str, version_name: str):
        versions = self.list_versions(project_href)
        for v in versions:
            if v.get("versionName", "").lower() == version_name.lower():
                return v
        return versions[0] if versions else None

    # ── BOM Components ────────────────────────────────────────────────────────

    def list_components(self, version_href: str):
        data = self._get(
            f"{version_href}/components",
            "application/vnd.blackducksoftware.bill-of-materials-6+json",
            params={"limit": 500},
        )
        return data.get("items", [])

    def list_vulnerable_components(self, version_href: str):
        data = self._get(
            f"{version_href}/vulnerable-bom-components",
            "application/vnd.blackducksoftware.bill-of-materials-6+json",
            params={"limit": 500},
        )
        return data.get("items", [])
