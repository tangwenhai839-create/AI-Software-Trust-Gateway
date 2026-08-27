"""AI Software Trust Gateway - 软件用途与能力理解分析器 (Deterministic Purpose Profile Extractor)
从不可信的 README 与元数据中提取事实声明，防范提示注入。
"""
import os
import re
from pathlib import Path
from typing import List

from backend.app.core.security import redact_secrets
from backend.app.domain.models import PurposeProfile


class PurposeExtractor:
    """提取软件声明用途与预期能力"""

    @classmethod
    def read_readme_excerpt(cls, repo_dir: str, max_chars: int = 5000) -> str:
        root_path = Path(repo_dir).resolve()
        for cand in ["README.md", "README.txt", "readme.md", "README.rst"]:
            readme_file = root_path / cand
            if readme_file.exists():
                try:
                    with open(readme_file, "r", encoding="utf-8", errors="ignore") as handle:
                        return handle.read(max_chars)
                except OSError:
                    return ""
        return ""

    @classmethod
    def extract_purpose(cls, repo_dir: str, scan_id: str) -> PurposeProfile:
        root_path = Path(repo_dir).resolve()
        readme_content = ""

        readme_content = cls.read_readme_excerpt(repo_dir, max_chars=5000)

        # 确定性提取标题与摘要
        summary = "未提供项目详细说明"
        declared_capabilities: List[str] = []
        expected_external_services: List[str] = []

        if readme_content:
            lines = [l.strip() for l in readme_content.splitlines() if l.strip()]
            for line in lines:
                if line.startswith("#"):
                    summary = line.lstrip("#").strip()
                    break
                elif len(line) > 20 and not line.startswith("!") and not line.startswith("["):
                    summary = line[:200]
                    break

            # 简要能力关键词提取
            text_lower = readme_content.lower()
            if "image" in text_lower or "photo" in text_lower or "picture" in text_lower:
                declared_capabilities.append("image_processing")
            if "download" in text_lower or "fetch" in text_lower or "crawler" in text_lower or "scraper" in text_lower:
                declared_capabilities.append("web_scraping_or_download")
            if "cli" in text_lower or "command line" in text_lower:
                declared_capabilities.append("cli_tool")
            if "api" in text_lower or "server" in text_lower:
                declared_capabilities.append("web_service")
            if "mcp" in text_lower or "agent" in text_lower:
                declared_capabilities.append("ai_agent_tool")

            # 提取显式声明的外部域名/服务
            urls = re.findall(r'https?://([a-zA-Z0-9_\-\.]+)', readme_content)
            for u in set(urls):
                if not u.startswith("github.com") and not u.startswith("badge") and not u.startswith("shields.io"):
                    expected_external_services.append(u)

        return PurposeProfile(
            scan_id=scan_id,
            summary=summary,
            declared_capabilities=declared_capabilities,
            expected_behaviors=[],
            expected_external_services=expected_external_services[:5],
            model_metadata={"readme_chars": len(readme_content)},
        )
