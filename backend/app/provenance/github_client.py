"""AI Software Trust Gateway - 项目溯源与声誉分析器 (GitHub Provenance Analyzer)
"""
from typing import Any, Dict, Optional
import httpx

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.core.security import normalize_and_validate_github_url


class ProvenanceAnalyzer:
    """收集开源项目基本声誉、创建时间、Star 数与许可证元数据"""

    @classmethod
    async def analyze_github_repo(cls, target_url: str) -> Dict[str, Any]:
        """
        获取 GitHub 仓库基本溯源信息并评估有限信誉信号。
        缺少 Token 或请求失败时输出未知，不得惩罚私有或小众项目。
        """
        provenance_data: Dict[str, Any] = {
            "source": "github",
            "stars": 0,
            "forks": 0,
            "open_issues": 0,
            "created_at": None,
            "updated_at": None,
            "default_branch": "main",
            "license": "unknown",
            "trust_signals": [],
            "risk_signals": [],
        }

        try:
            _, owner, repo = normalize_and_validate_github_url(target_url)
            headers = {"User-Agent": "ASTG-Provenance/1.0"}
            if settings.GITHUB_TOKEN:
                headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"

            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(api_url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    provenance_data["stars"] = data.get("stargazers_count", 0)
                    provenance_data["forks"] = data.get("forks_count", 0)
                    provenance_data["open_issues"] = data.get("open_issues_count", 0)
                    provenance_data["created_at"] = data.get("created_at")
                    provenance_data["updated_at"] = data.get("updated_at")
                    provenance_data["default_branch"] = data.get("default_branch", "main")

                    lic = data.get("license")
                    if lic and isinstance(lic, dict):
                        provenance_data["license"] = lic.get("spdx_id", lic.get("name", "custom"))

                    # 生成溯源信誉信号
                    if provenance_data["stars"] > 500:
                        provenance_data["trust_signals"].append("项目具有广泛的社区关注度 (>500 Stars)")
                    if provenance_data["license"] != "unknown":
                        provenance_data["trust_signals"].append(f"明确声明开源许可证: {provenance_data['license']}")

                    # 异常风险信号检测
                    if data.get("fork", False) and provenance_data["stars"] < 5:
                        provenance_data["risk_signals"].append("项目为低关注度 Fork 仓库")
        except Exception as e:
            logger.info("获取 GitHub 仓库声誉数据跳过或异常 (标记为未知)", error=str(e))

        return provenance_data
