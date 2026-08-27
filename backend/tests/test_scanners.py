"""静态扫描器与去重融合测试
"""
import pytest
from backend.app.domain.enums import FindingCategory, Severity
from backend.app.domain.models import Evidence, Finding
from backend.app.scanners.deduplicator import FindingDeduplicator
from backend.app.scanners.regex_rules import NativeASTPythonScanner, NativeJSPatternScanner


@pytest.mark.asyncio
async def test_python_ast_scanner_on_suspicious_fixture():
    scanner = NativeASTPythonScanner()
    findings = await scanner.scan("fixtures/suspicious_stealer", scan_id="test-scan")

    categories = [f.category for f in findings]
    assert FindingCategory.SENSITIVE_FILE_ACCESS in categories
    assert FindingCategory.NETWORK_EXFILTRATION in categories
    assert FindingCategory.DYNAMIC_EXECUTION in categories


@pytest.mark.asyncio
async def test_python_ast_scanner_on_benign_fixture():
    scanner = NativeASTPythonScanner()
    findings = await scanner.scan("fixtures/benign_image_tool", scan_id="test-scan")
    assert len(findings) == 0


def test_finding_deduplication():
    f1 = Finding(
        scan_id="s1",
        scanner_name="scanner_a",
        fingerprint="fp1",
        category=FindingCategory.DYNAMIC_EXECUTION,
        title="eval detected",
        severity=Severity.MEDIUM,
        confidence=0.7,
        file_path="main.py",
        line_start=10,
        evidences=[Evidence(kind="code", source="scanner_a", location="main.py:10", excerpt_redacted="eval(x)", sha256="h1")]
    )
    f2 = Finding(
        scan_id="s1",
        scanner_name="scanner_b",
        fingerprint="fp2",
        category=FindingCategory.DYNAMIC_EXECUTION,
        title="eval detected high",
        severity=Severity.HIGH,
        confidence=0.8,
        file_path="main.py",
        line_start=10,
        evidences=[Evidence(kind="code", source="scanner_b", location="main.py:10", excerpt_redacted="eval(x)", sha256="h1")]
    )

    merged = FindingDeduplicator.deduplicate_and_fuse([f1, f2])
    assert len(merged) == 1
    assert merged[0].severity == Severity.HIGH
    assert merged[0].confidence >= 0.8
