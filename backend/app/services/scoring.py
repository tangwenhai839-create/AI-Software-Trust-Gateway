"""AI Software Trust Gateway - 确定性风险与安全评分引擎 (Deterministic Scoring Engine)
基于 mvp-static-v1 版本化规则计算安全分、风险等级、置信度与三维覆盖率。
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.app.domain.enums import RiskLevel, Severity
from backend.app.domain.models import Dependency, Finding, Score
from backend.app.core.resources import resource_path


class DeterministicScoringEngine:
    """确定性评分引擎：相同输入必须产生完全一致的分数与等级"""

    def __init__(self, config_path: str = None):
        self.config_version = "mvp-static-v1"
        self.weights = {
            "static_code": 0.45,
            "dependencies": 0.35,
            "provenance": 0.15,
            "ai_reasoning": 0.05,
        }
        self.severity_penalties = {
            "critical": 40,
            "high": 20,
            "medium": 8,
            "low": 3,
            "info": 0,
        }
        resolved_config = Path(config_path).resolve() if config_path else resource_path("rules/scoring/mvp-static-v1.json")
        if resolved_config.exists():
            try:
                with open(resolved_config, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    self.config_version = cfg.get("version", self.config_version)
                    self.weights = cfg.get("weights", self.weights)
                    self.severity_penalties = cfg.get("severity_penalties", self.severity_penalties)
            except Exception:
                pass

    def calculate_score(
        self,
        scan_id: str,
        findings: List[Finding],
        dependencies: List[Dependency],
        provenance: Dict[str, Any],
        ai_assessment: Optional[Dict[str, Any]],
        coverage: Dict[str, float],
    ) -> Score:
        # 1. 静态代码风险分 (0 - 100)
        static_penalty = 0
        has_critical_finding = False
        has_high_finding = False

        for f in findings:
            sev = f.severity.value if isinstance(f.severity, Severity) else str(f.severity).lower()
            static_penalty += self.severity_penalties.get(sev, 0)
            if sev == "critical":
                has_critical_finding = True
            elif sev == "high":
                has_high_finding = True

        static_risk = min(100.0, float(static_penalty))

        # 2. 依赖漏洞风险分 (0 - 100)
        dep_penalty = 0
        has_critical_vuln = False
        for dep in dependencies:
            for vuln in dep.vulnerabilities:
                v_sev = vuln.severity.value if isinstance(vuln.severity, Severity) else str(vuln.severity).lower()
                dep_penalty += self.severity_penalties.get(v_sev, 0)
                if v_sev == "critical":
                    has_critical_vuln = True

        dep_risk = min(100.0, float(dep_penalty))

        # 3. 溯源风险分 (0 - 100)
        prov_risk = 10.0  # 基础未知风险
        trust_signals = provenance.get("trust_signals", [])
        risk_signals = provenance.get("risk_signals", [])
        prov_risk += len(risk_signals) * 20.0
        prov_risk = max(0.0, prov_risk - len(trust_signals) * 10.0)
        prov_risk = min(100.0, prov_risk)

        # 4. AI 综合风险分 (0 - 100)
        ai_risk = 20.0
        if ai_assessment and "overall_assessment" in ai_assessment:
            prob = ai_assessment["overall_assessment"].get("risk_probability", 0.2)
            ai_risk = min(100.0, max(0.0, prob * 100.0))

        # 5. 加权计算总风险分
        w_static = self.weights.get("static_code", 0.45)
        w_dep = self.weights.get("dependencies", 0.35)
        w_prov = self.weights.get("provenance", 0.15)
        w_ai = self.weights.get("ai_reasoning", 0.05)

        total_weight = w_static + w_dep + w_prov + w_ai
        weighted_risk = (
            static_risk * w_static +
            dep_risk * w_dep +
            prov_risk * w_prov +
            ai_risk * w_ai
        ) / total_weight

        # 安全分 = 100 - 加权风险
        raw_safety_score = max(0, min(100, int(round(100.0 - weighted_risk))))
        final_safety_score = raw_safety_score
        caps_applied: List[str] = []

        # 6. 应用严重度安全分上限 (Score Caps)
        if has_critical_finding and final_safety_score > 39:
            final_safety_score = 39
            caps_applied.append("存在已证实的严重安全发现 (Critical Finding)，安全分上限限制为 39 (高风险)")
        elif has_high_finding and final_safety_score > 69:
            final_safety_score = 69
            caps_applied.append("存在已证实的高危安全发现 (High Finding)，安全分上限限制为 69 (中风险)")

        if has_critical_vuln and final_safety_score > 49:
            final_safety_score = 49
            caps_applied.append("存在已知的严重依赖漏洞 (Critical CVE)，安全分上限限制为 49")

        final_risk_score = 100 - final_safety_score

        # 7. 等级判定
        if final_safety_score >= 90:
            risk_level = RiskLevel.SAFE
        elif final_safety_score >= 70:
            risk_level = RiskLevel.LOW
        elif final_safety_score >= 40:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.HIGH

        # 8. 三维立体覆盖率与置信度计算
        # 完整分析维度权重: 静态代码(40%) + 依赖漏洞(30%) + 动态沙箱执行(30%)
        cov_static = float(coverage.get("static", 1.0))
        cov_deps = float(coverage.get("dependencies", 1.0))
        cov_dyn = float(coverage.get("dynamic", 0.0))

        overall_coverage = cov_static * 0.40 + cov_deps * 0.30 + cov_dyn * 0.30

        confidence = 0.85 if findings else 0.90
        if cov_static < 1.0 or cov_deps < 1.0:
            confidence = max(0.40, confidence - 0.20)
        if len(caps_applied) > 0:
            confidence = min(0.98, confidence + 0.10)

        components_json = {
            "static_code_risk": round(static_risk, 1),
            "dependencies_risk": round(dep_risk, 1),
            "provenance_risk": round(prov_risk, 1),
            "ai_reasoning_risk": round(ai_risk, 1),
            "weighted_risk": round(weighted_risk, 1),
            "raw_safety_score": raw_safety_score,
            "final_safety_score": final_safety_score,
            "coverage_breakdown": {
                "static_coverage": round(cov_static, 2),
                "dependencies_coverage": round(cov_deps, 2),
                "dynamic_coverage": round(cov_dyn, 2),
                "total_coverage": round(overall_coverage, 2),
            }
        }

        return Score(
            scan_id=scan_id,
            scoring_version=self.config_version,
            safety_score=final_safety_score,
            risk_score=final_risk_score,
            risk_level=risk_level,
            confidence=round(confidence, 2),
            coverage=round(overall_coverage, 2),
            components=components_json,
            caps_applied=caps_applied,
        )
