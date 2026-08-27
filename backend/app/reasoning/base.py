"""AI Software Trust Gateway - AI 推理提供者抽象基类 (AI Provider Base)
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from backend.app.domain.models import Dependency, Finding, PurposeProfile


class AIReasoningProvider(ABC):
    """AI 安全推理提供者接口"""

    @property
    @abstractmethod
    def provider_type(self) -> str:
        """提供者类型"""
        pass

    @abstractmethod
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
        """
        输入受限、脱敏上下文，返回符合 ai-output-v1.json 的结构化结果。
        """
        pass
