"""AI Software Trust Gateway - 默认离线/禁用 AI 提供者 (Disabled Provider)
在零外部模型调用下提供确定性的基础用途一致性描述。
"""
from typing import Any, Dict, List, Optional

from backend.app.domain.models import Dependency, Finding, PurposeProfile
from backend.app.reasoning.base import AIReasoningProvider


class DisabledAIProvider(AIReasoningProvider):
    """默认安全提供者，不向任何第三方发起网络请求"""

    @property
    def provider_type(self) -> str:
        return "disabled"

    async def reason(
        self,
        scan_id: str,
        purpose_profile: PurposeProfile,
        target_info: Dict[str, Any],
        findings: List[Finding],
        coverage: Dict[str, float],
        dependencies: Optional[List[Dependency]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        dynamic_analysis: Optional[Dict[str, Any]] = None,
        untrusted_readme_excerpt: str = "",
    ) -> Optional[Dict[str, Any]]:
        # 生成确定性基线评估
        finding_assessments = []
        for f in findings:
            finding_assessments.append({
                "finding_id": f.id,
                "behavior": f.title,
                "likely_reason": "静态规则命中的特征模式",
                "purpose_alignment": "unclear",
                "benign_explanations": ["功能性调用或依赖封装"],
                "malicious_hypotheses": ["非预期凭据读取或代码执行隐患"],
                "risk_probability": 0.5 if f.severity.value in ("high", "critical") else 0.2,
                "confidence": 0.5,
                "evidence_refs": [e.id for e in f.evidences],
                "needs_verification": True,
                "verification_steps": ["建议人工结合上下文代码审查"],
            })

        return {
            "schema_version": "1.0",
            "purpose_assessment": f"软件声明用途: {purpose_profile.summary} (基于静态元数据分析)",
            "finding_assessments": finding_assessments,
            "overall_assessment": {
                "risk_probability": 0.2,
                "confidence": 0.6,
                "summary": "AI 综合推理已禁用 (本地纯静态模式)，所有评估均由确定性规则生成。",
                "limitations": [
                    "未启用 LLM 语意理解",
                    "仅基于确定性静态规则",
                    "未执行沙箱动态验证"
                ],
            },
        }
