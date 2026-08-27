"""HTML 报告 XSS 防御与结构一致性测试
"""
import pytest
from backend.app.domain.enums import RiskLevel, Severity
from backend.app.domain.models import Artifact, Finding, Project, PurposeProfile, Scan, Score
from backend.app.reports.reporter import ReportGenerator


def test_html_report_escapes_xss_payloads(tmp_path):
    generator = ReportGenerator(artifacts_base_dir=str(tmp_path))

    scan = Scan(id="xss-scan", target_url="https://github.com/evil/<script>alert(1)</script>")
    project = Project(id="p1", canonical_url="https://github.com/evil/<script>alert(1)</script>")
    artifact = Artifact(id="a1", commit_sha="<img src=x onerror=alert(2)>", sha256="hash123", languages=["python"])
    score = Score(scan_id="xss-scan", safety_score=85, risk_score=15, risk_level=RiskLevel.LOW)

    finding = Finding(
        id="f1", scan_id="xss-scan", scanner_name="sc", fingerprint="fp",
        title="<svg onload=alert(3)>", severity=Severity.MEDIUM,
        confidence=0.8, file_path="<iframe src=evil.com>", line_start=1
    )
    purpose = PurposeProfile(scan_id="xss-scan", summary="<b>malicious summary</b>")

    json_path, html_path, _, _ = generator.generate_reports(
        scan=scan, project=project, artifact=artifact, score=score,
        findings=[finding], dependencies=[], provenance={},
        purpose=purpose, ai_analysis={}, coverage={"static": 1.0, "dependencies": 1.0}
    )

    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    # 验证所有的 XSS 载荷均已被安全实体转义
    assert "<script>alert(1)</script>" not in html_content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_content

    assert "<img src=x onerror=alert(2)>" not in html_content
    assert "&lt;img src=x onerror=alert(2)&gt;" in html_content

    assert "<svg onload=alert(3)>" not in html_content
    assert "&lt;svg onload=alert(3)&gt;" in html_content
