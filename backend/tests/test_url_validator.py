"""URL 与 SSRF 防御单元测试
"""
import pytest
from backend.app.core.errors import SSRFValidationError
from backend.app.core.security import normalize_and_validate_github_url, validate_outbound_url_ssrf, redact_secrets


def test_valid_github_urls():
    url, owner, repo = normalize_and_validate_github_url("https://github.com/psf/requests")
    assert url == "https://github.com/psf/requests"
    assert owner == "psf"
    assert repo == "requests"

    url2, owner2, repo2 = normalize_and_validate_github_url("https://github.com/torvalds/linux.git")
    assert url2 == "https://github.com/torvalds/linux"
    assert owner2 == "torvalds"
    assert repo2 == "linux"


def test_invalid_and_malicious_urls():
    with pytest.raises(SSRFValidationError):
        normalize_and_validate_github_url("http://github.com/owner/repo")  # 非 HTTPS

    with pytest.raises(SSRFValidationError):
        normalize_and_validate_github_url("https://evil.com/owner/repo")

    with pytest.raises(SSRFValidationError):
        normalize_and_validate_github_url("https://github.com/../escape")


def test_ssrf_blocked_hosts():
    with pytest.raises(SSRFValidationError):
        validate_outbound_url_ssrf("http://127.0.0.1:8000/api")

    with pytest.raises(SSRFValidationError):
        validate_outbound_url_ssrf("http://localhost/test")

    with pytest.raises(SSRFValidationError):
        validate_outbound_url_ssrf("http://169.254.169.254/latest/meta-data")


def test_secret_redaction():
    fake_openai_key = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"
    text = f"Authorization: Bearer secret_token_12345678901234567890\nOpenAI key: {fake_openai_key}"
    sanitized = redact_secrets(text)
    assert "secret_token" not in sanitized
    assert "sk-abcdefgh" not in sanitized
    assert "[REDACTED_BEARER_TOKEN]" in sanitized or "[REDACTED_API_KEY]" in sanitized
