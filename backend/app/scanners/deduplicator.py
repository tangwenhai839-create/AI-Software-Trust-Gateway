"""AI Software Trust Gateway - 发现项去重与多源证据融合引擎 (Finding Deduplicator & Evidence Fusion)
"""
from typing import Dict, List
from backend.app.domain.models import Finding


class FindingDeduplicator:
    """对不同扫描器上报的重复或重叠发现项进行稳定去重与证据融合"""

    @classmethod
    def deduplicate_and_fuse(cls, findings: List[Finding]) -> List[Finding]:
        """
        合并同位置/同类型的重复发现，聚合多源 Evidence 并提升综合置信度。
        """
        if not findings:
            return []

        # 聚类键: (category, file_path, line_start)
        clusters: Dict[str, Finding] = {}

        for f in findings:
            cluster_key = f"{f.category.value}:{f.file_path}:{f.line_start}"

            if cluster_key not in clusters:
                clusters[cluster_key] = f
            else:
                existing = clusters[cluster_key]
                # 更新置信度为最大值
                existing.confidence = max(existing.confidence, f.confidence)

                # 融合 Evidences (按 source:sha256 去重)
                existing_evidence_keys = {f"{e.source}:{e.sha256}" for e in existing.evidences}
                for ev in f.evidences:
                    ev_key = f"{ev.source}:{ev.sha256}"
                    if ev_key not in existing_evidence_keys:
                        existing.evidences.append(ev)
                        existing_evidence_keys.add(ev_key)

                # 保留更高的严重级别 (Critical > High > Medium > Low > Info)
                sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                if sev_order.get(f.severity.value, 0) > sev_order.get(existing.severity.value, 0):
                    existing.severity = f.severity
                    existing.title = f.title

                # 多个不同扫描器交叉印证时，适度提升置信度 (最高 0.98)
                existing_sources = {e.source.split(":")[0] for e in existing.evidences}
                if len(existing_sources) > 1:
                    existing.confidence = min(0.98, existing.confidence + 0.1)

        return list(clusters.values())
