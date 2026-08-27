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
        # Some local proxy/VPN clients resolve allow-listed public domains to
        # RFC 2544 Fake-IP addresses (198.18.0.0/15). The parser above already
        # restricts this path to the exact HTTPS github.com domain, so permit
        # only that proxy range for that one host. All other restricted
        # destinations remain blocked.
        validate_outbound_url_ssrf(canonical_url, allow_proxy_fake_ip_for={"github.com"})
        return canonical_url, owner, repo
