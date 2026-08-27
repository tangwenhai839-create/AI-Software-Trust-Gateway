"""AI Software Trust Gateway - CLI REST API 客户端
"""
from typing import Any, Dict, Optional
import httpx


class ASTGClient:
    """与 ASTG FastAPI 控制平面交互的 HTTP 客户端"""

    def __init__(self, base_url: str = "http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip("/")

    def _get_client(self, timeout: float = 10.0) -> httpx.Client:
        # trust_env=False 避免 Windows 本地网络代理干扰 127.0.0.1 通信
        return httpx.Client(base_url=self.base_url, timeout=timeout, trust_env=False)

    def create_scan(self, url: str, ref: str = "main", profile: str = "mvp-static-v1", ai_enabled: bool = False) -> Dict[str, Any]:
        endpoint = "/api/v1/scans"
        payload = {
            "source": {"type": "github" if not url.startswith("local://") else "local", "url": url, "ref": ref},
            "profile": profile,
            "ai": {"enabled": ai_enabled, "provider": "openai_compatible" if ai_enabled else "disabled"},
        }
        with self._get_client(timeout=30.0) as client:
            resp = client.post(endpoint, json=payload)
            resp.raise_for_status()
            return resp.json()

    def get_scan(self, scan_id: str) -> Dict[str, Any]:
        endpoint = f"/api/v1/scans/{scan_id}"
        with self._get_client(timeout=10.0) as client:
            resp = client.get(endpoint)
            resp.raise_for_status()
            return resp.json()

    def get_findings(self, scan_id: str, severity: Optional[str] = None) -> Dict[str, Any]:
        endpoint = f"/api/v1/scans/{scan_id}/findings"
        params = {}
        if severity:
            params["severity"] = severity
        with self._get_client(timeout=10.0) as client:
            resp = client.get(endpoint, params=params)
            resp.raise_for_status()
            return resp.json()

    def get_dependencies(self, scan_id: str) -> Dict[str, Any]:
        endpoint = f"/api/v1/scans/{scan_id}/dependencies"
        with self._get_client(timeout=10.0) as client:
            resp = client.get(endpoint)
            resp.raise_for_status()
            return resp.json()

    def get_report_json(self, scan_id: str) -> Dict[str, Any]:
        endpoint = f"/api/v1/scans/{scan_id}/report.json"
        with self._get_client(timeout=15.0) as client:
            resp = client.get(endpoint)
            resp.raise_for_status()
            return resp.json()

    def download_report_html(self, scan_id: str) -> str:
        endpoint = f"/api/v1/scans/{scan_id}/report.html"
        with self._get_client(timeout=15.0) as client:
            resp = client.get(endpoint)
            resp.raise_for_status()
            return resp.text

    def get_capabilities(self) -> Dict[str, Any]:
        endpoint = "/api/v1/capabilities"
        with self._get_client(timeout=10.0) as client:
            resp = client.get(endpoint)
            resp.raise_for_status()
            return resp.json()
