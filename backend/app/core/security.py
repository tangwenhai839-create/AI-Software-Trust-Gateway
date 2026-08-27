"""AI Software Trust Gateway - 安全核心 (SSRF 防御、URL 规范化、秘密脱敏)
"""
import ipaddress
import re
import socket
from typing import Optional, Set, Tuple
from urllib.parse import urlparse

from backend.app.core.errors import SSRFValidationError

# 严格匹配合法 GitHub 仓库 URL
GITHUB_URL_REGEX = re.compile(
    r"^https://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+?)(?:\.git)?/?$"
)

# 敏感信息脱敏正则
SECRET_PATTERNS = [
    # OpenAI / Anthropic / Generic API Keys
    (re.compile(r"(sk-[a-zA-Z0-9_-]{20,})"), "[REDACTED_API_KEY]"),
    (re.compile(r"(ghp_[a-zA-Z0-9]{36})"), "[REDACTED_GH_TOKEN]"),
    (re.compile(r"(gho_[a-zA-Z0-9]{36})"), "[REDACTED_GH_OAUTH]"),
    (re.compile(r"(github_pat_[a-zA-Z0-9_]{60,})"), "[REDACTED_GH_PAT]"),
    (re.compile(r"(AKIA[0-9A-Z]{16})"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)(bearer\s+)([a-zA-Z0-9_\-\.]{20,})"), r"\1[REDACTED_BEARER_TOKEN]"),
    (re.compile(r"(?i)(password\s*[:=]\s*['\"])([^'\"]{3,})(['\"])"), r"\1[REDACTED_PASSWORD]\3"),
    (re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]

BLOCKED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "metadata.google.internal",
    "169.254.169.254",  # AWS/GCP/Azure instance metadata
    "instance-data",
}


def normalize_and_validate_github_url(url_str: str) -> Tuple[str, str, str]:
    """
    规范化并验证 GitHub URL。
    返回 (canonical_url, owner, repo)
    """
    if not url_str or not isinstance(url_str, str):
        raise SSRFValidationError("URL 不能为空")

    clean_url = url_str.strip()
    match = GITHUB_URL_REGEX.match(clean_url)
    if not match:
        raise SSRFValidationError(
            f"非法的 GitHub 仓库 URL: '{clean_url}'。格式必须为 'https://github.com/owner/repo'"
        )

    owner, repo = match.group(1), match.group(2)
    # 防范 .. 穿越命名
    if owner in (".", "..") or repo in (".", ".."):
        raise SSRFValidationError("仓库所有者或名称包含非法字符")

    canonical_url = f"https://github.com/{owner}/{repo}"
    return canonical_url, owner, repo


def validate_outbound_url_ssrf(
    url_str: str,
    allow_proxy_fake_ip_for: Optional[Set[str]] = None,
) -> bool:
    """
    验证外发 HTTP URL 是否安全，拦截内网、回环、本地及元数据地址。
    """
    try:
        parsed = urlparse(url_str)
        if parsed.scheme not in ("http", "https"):
            raise SSRFValidationError(f"不支持的协议方案: {parsed.scheme}")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFValidationError("URL 缺少有效主机名")

        hostname_lower = hostname.lower()
        if hostname_lower in BLOCKED_HOSTS:
            raise SSRFValidationError(f"禁止访问被拦截的主机: {hostname}")

        # 解析实际 IP 地址并检测私有 / 回环 / 保留地址
        try:
            addr_info = socket.getaddrinfo(hostname, None)
        except socket.gaierror as e:
            raise SSRFValidationError(f"无法解析主机名 '{hostname}': {str(e)}")

        allowed_fake_ip_hosts = {host.lower() for host in (allow_proxy_fake_ip_for or set())}
        proxy_fake_ip_network = ipaddress.ip_network("198.18.0.0/15")
        for item in addr_info:
            ip_str = item[4][0]
            ip = ipaddress.ip_address(ip_str)
            is_allowed_proxy_fake_ip = (
                hostname_lower in allowed_fake_ip_hosts
                and ip.version == 4
                and ip in proxy_fake_ip_network
            )
            if not is_allowed_proxy_fake_ip and (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
                or ip_str == "169.254.169.254"
            ):
                raise SSRFValidationError(
                    f"安全拦截: 主机 '{hostname}' 解析到非公网受限 IP ({ip_str})"
                )

        return True
    except SSRFValidationError:
        raise
    except Exception as e:
        raise SSRFValidationError(f"URL 安全校验失败: {str(e)}")


def redact_secrets(text: str) -> str:
    """
    对不可信文本、代码摘录或日志进行敏感信息脱敏。
    """
    if not text:
        return ""

    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized
