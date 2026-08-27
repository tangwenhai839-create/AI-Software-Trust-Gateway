"""AI 推理与 Schema / 证据引用完整性校验测试
"""
import pytest
from backend.app.core.errors import AIValidationError
from backend.app.domain.enums import FindingCategory, Severity
from backend.app.domain.models import Evidence, Finding
from backend.app.reasoning.validator import AIOutputValidator


def test_valid_ai_output_passes():
    validator = AIOutputValidator()
    ev = Evidence(id="E-1", finding_id="F-1", kind="code", source="src", location="loc", excerpt_redacted="exc")
    finding = Finding(
        id="F-1", scan_id="s1", scanner_name="sc", fingerprint="fp",
        category=FindingCategory.DYNAMIC_EXECUTION, title="eval",
        severity=Severity.HIGH, confidence=0.8, file_path="main.py", line_start=1,
        evidences=[ev]
    )

    valid_payload = {
        "schema_version": "1.0",
        "purpose_assessment": "Verified image tool",
        "finding_assessments": [
            {
                "finding_id": "F-1",
                "behavior": "eval call",
                "likely_reason": "plugin loader",
                "purpose_alignment": "aligned",
                "benign_explanations": ["harmless config"],
                "malicious_hypotheses": ["unlikely"],
                "risk_probability": 0.1,
                "confidence": 0.8,
                "evidence_refs": ["E-1"],
                "needs_verification": False,
                "verification_steps": [],
            }
        ],
        "overall_assessment": {
            "risk_probability": 0.1,
            "confidence": 0.8,
            "summary": "Low risk",
            "limitations": ["Static check only"]
        }
    }

    assert validator.validate(valid_payload, [finding]) is True


def test_ai_hallucinated_finding_id_fails():
    validator = AIOutputValidator()
    invalid_payload = {
        "schema_version": "1.0",
        "purpose_assessment": "Verified image tool",
        "finding_assessments": [
            {
                "finding_id": "F-NON-EXISTENT",
                "behavior": "eval call",
                "likely_reason": "plugin loader",
                "purpose_alignment": "aligned",
                "benign_explanations": [],
                "malicious_hypotheses": [],
                "risk_probability": 0.1,
                "confidence": 0.8,
                "evidence_refs": [],
                "needs_verification": False,
                "verification_steps": [],
            }
        ],
        "overall_assessment": {
            "risk_probability": 0.1,
            "confidence": 0.8,
            "summary": "Low risk",
            "limitations": []
        }
    }

    with pytest.raises(AIValidationError):
        validator.validate(invalid_payload, [])
