"""确定性评分引擎与上限规则单元测试
"""
import pytest
from backend.app.domain.enums import FindingCategory, RiskLevel, Severity
from backend.app.domain.models import Evidence, Finding, Vulnerability, Dependency
from backend.app.services.scoring import DeterministicScoringEngine


def test_clean_repo_scores_high():
    engine = DeterministicScoringEngine()
    score = engine.calculate_score(
        scan_id="s1",
        findings=[],
        dependencies=[],
        provenance={"trust_signals": ["社区关注度高"]},
        ai_assessment=None,
        coverage={"static": 1.0, "dependencies": 1.0},
    )
    assert score.safety_score >= 90
    assert score.risk_level == RiskLevel.SAFE
    assert len(score.caps_applied) == 0


def test_critical_finding_triggers_score_cap():
    engine = DeterministicScoringEngine()
    crit_finding = Finding(
        scan_id="s2",
        scanner_name="astg_ast",
        fingerprint="fp_crit",
        category=FindingCategory.COMMAND_EXECUTION,
        title="Remote Command Execution",
        severity=Severity.CRITICAL,
        confidence=0.95,
        file_path="exploit.py",
        line_start=1,
    )
    score = engine.calculate_score(
        scan_id="s2",
        findings=[crit_finding],
        dependencies=[],
        provenance={},
        ai_assessment=None,
        coverage={"static": 1.0, "dependencies": 1.0},
    )
    assert score.safety_score <= 39
    assert score.risk_level == RiskLevel.HIGH
    assert any("Critical Finding" in cap for cap in score.caps_applied)


def test_high_finding_triggers_score_cap():
    engine = DeterministicScoringEngine()
    high_finding = Finding(
        scan_id="s3",
        scanner_name="astg_ast",
        fingerprint="fp_high",
        category=FindingCategory.SENSITIVE_FILE_ACCESS,
        title="SSH Key Access",
        severity=Severity.HIGH,
        confidence=0.90,
        file_path="stealer.py",
        line_start=5,
    )
    score = engine.calculate_score(
        scan_id="s3",
        findings=[high_finding],
        dependencies=[],
        provenance={},
        ai_assessment=None,
        coverage={"static": 1.0, "dependencies": 1.0},
    )
    assert score.safety_score <= 69
    assert score.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    assert any("High Finding" in cap for cap in score.caps_applied)


def test_dependency_vulnerability_is_warning_not_red_score_cap():
    engine = DeterministicScoringEngine()
    dependency = Dependency(
        name="example-package",
        version="1.0.0",
        vulnerabilities=[Vulnerability(advisory_id="CVE-2025-0001", severity=Severity.CRITICAL)],
    )
    score = engine.calculate_score(
        scan_id="s4",
        findings=[],
        dependencies=[dependency],
        provenance={},
        ai_assessment=None,
        coverage={"static": 1.0, "dependencies": 1.0},
    )
    assert score.risk_level != RiskLevel.HIGH
    assert not any("CVE" in cap or "依赖漏洞" in cap for cap in score.caps_applied)
