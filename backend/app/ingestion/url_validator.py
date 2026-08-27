"""AI Software Trust Gateway - URL 校验器与 SSRF 拦截
"""
from typing import Tuple
from backend.app.core.security import normalize_and_validate_github_url, validate_outbound_url_ssrf


class GitHubUrlValidator:
    """验证并规范化 GitHub URL，确保安全合规"""

    @staticmethod
    def validate(url_str: str) -> Tuple[str, str, str]:
        """
        验证 URL 格式并确认主机安全性。
        返回: (canonical_url, owner, repo)
        """
        canonical_url, owner, repo = normalize_and_validate_github_url(url_str)
        # SSRF 检查主机安全性
        validate_outbound_url_ssrf(canonical_url)
        return canonical_url, owner, repo
