"""AI Software Trust Gateway - AI 输出 Schema 与引用完整性校验器 (AI Validator)
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Set
import jsonschema

from backend.app.core.errors import AIValidationError
from backend.app.core.resources import resource_path
from backend.app.domain.models import Finding


class AIOutputValidator:
    """严格校验 AI 输出 JSON 契约以及引用发现 ID / 证据 ID 的合法性"""

    def __init__(self, schema_path: str = None):
        self.schema = None
        resolved_schema = resource_path("schemas/ai-output-v1.json") if schema_path is None else Path(schema_path).resolve()
        if resolved_schema.exists():
            with open(resolved_schema, "r", encoding="utf-8") as f:
                self.schema = json.load(f)

    def validate(self, ai_output: Dict[str, Any], valid_findings: List[Finding]) -> bool:
        """
        验证 AI 输出：
        1. JSON Schema 格式合规
        2. finding_id 必须在 valid_findings 中存在
        3. evidence_refs 必须为该 finding 下已有的证据 ID
        """
        if not isinstance(ai_output, dict):
            raise AIValidationError("AI 输出必须为 JSON Object")

        if self.schema:
            try:
                jsonschema.validate(instance=ai_output, schema=self.schema)
            except jsonschema.ValidationError as e:
                raise AIValidationError(f"AI 输出未能通过 Schema 校验: {e.message}")

        # 校验 finding_id 与 evidence_refs
        valid_finding_map = {f.id: {e.id for e in f.evidences} for f in valid_findings}

        for item in ai_output.get("finding_assessments", []):
            fid = item.get("finding_id")
            if fid not in valid_finding_map:
                raise AIValidationError(f"AI 虚构了不存在的 finding_id: {fid}")

            allowed_ev_ids = valid_finding_map[fid]
            for ev_ref in item.get("evidence_refs", []):
                if ev_ref not in allowed_ev_ids and ev_ref != fid:
                    raise AIValidationError(f"AI 虚构了不存在的 evidence_ref: {ev_ref} (finding {fid})")

        return True
