"""AI Software Trust Gateway - OSV 漏洞数据库客户端 (OSV API Client with Batch, Real CVSS & Fallback)
"""
import re
from typing import Any, Dict, List, Optional, Tuple
import httpx

from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.domain.enums import Severity
from backend.app.domain.models import Vulnerability


def calculate_cvss_score_from_vector(vector_str: str) -> Optional[float]:
    """根据 CVSS:3.x 向量字符串解析基础分值"""
    if not vector_str or not isinstance(vector_str, str):
        return None

    # 如果是直接的数字评分字符串 (e.g. "9.8", "7.5")
    try:
        val = float(vector_str.strip())
        if 0.0 <= val <= 10.0:
            return round(val, 1)
    except ValueError:
        pass

    # 解析 CVSS:3.1 / CVSS:3.0 向量
    metrics = dict(re.findall(r"([A-Z]+):([A-Z]+)", vector_str))
    if not metrics:
        return None

    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    pr_u_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c_map = {"N": 0.85, "L": 0.68, "H": 0.5}
    ui_map = {"N": 0.85, "R": 0.62}
    cia_map = {"H": 0.56, "L": 0.22, "N": 0.0}

    scope_changed = metrics.get("S") == "C"
    av = av_map.get(metrics.get("AV", "N"), 0.85)
    ac = ac_map.get(metrics.get("AC", "L"), 0.77)
    pr = (pr_c_map if scope_changed else pr_u_map).get(metrics.get("PR", "N"), 0.85)
    ui = ui_map.get(metrics.get("UI", "N"), 0.85)

    c = cia_map.get(metrics.get("C", "N"), 0.0)
    i = cia_map.get(metrics.get("I", "N"), 0.0)
    a = cia_map.get(metrics.get("A", "N"), 0.0)

    # ISS (Impact Sub-Score)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0

    if not scope_changed:
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif not scope_changed:
        score = min(10.0, impact + exploitability)
    else:
        score = min(10.0, 1.08 * (impact + exploitability))

    # 向上取整至 0.1
    import math
    return math.ceil(score * 10) / 10.0


class OSVClient:
    """查询 Open Source Vulnerabilities (OSV) API"""

    def __init__(self, api_url: Optional[str] = None, timeout: Optional[int] = None):
        self.api_url = api_url or settings.OSV_API_URL
        self.timeout = timeout or settings.OSV_TIMEOUT_SECONDS

    async def query_batch_vulnerabilities(
        self,
        queries: List[Dict[str, Any]]
    ) -> Tuple[List[List[Vulnerability]], bool]:
        """
        批量查询依赖漏洞。
        返回: (vulnerabilities_per_query, is_success)
        """
        if not queries:
            return [], True

        results: List[List[Vulnerability]] = [[] for _ in queries]
        payload = {"queries": queries}

        try:
            async with httpx.AsyncClient(timeout=float(self.timeout), trust_env=False) as client:
                resp = await client.post(self.api_url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    raw_results = data.get("results", [])
                    for idx, res in enumerate(raw_results):
                        vulns_data = res.get("vulns", [])
                        parsed_vulns = [self._parse_osv_item(v) for v in vulns_data]
                        results[idx] = parsed_vulns
                    return results, True
                else:
                    logger.warning("OSV API 请求返回非 200", status=resp.status_code)
                    return results, False
        except Exception as e:
            logger.warning("OSV 漏洞数据库查询离线或超时，降级为离线依赖审查", error=str(e))
            return results, False

    def _parse_osv_item(self, item: Dict[str, Any]) -> Vulnerability:
        advisory_id = item.get("id", "OSV-UNKNOWN")
        aliases = item.get("aliases", [])
        summary = item.get("summary", "")
        details = item.get("details", "")

        # 真实解析 CVSS 分数与严重度
        cvss_score = None
        severity_entries = item.get("severity", [])
        for entry in severity_entries:
            if entry.get("type") in ("CVSS_V3", "CVSS_V3.1", "CVSS_V2"):
                score_val = entry.get("score", "")
                parsed_score = calculate_cvss_score_from_vector(score_val)
                if parsed_score is not None:
                    cvss_score = parsed_score
                    break

        # 如果没有 CVSS 向量，从 database_specific / ecosystem_specific 中提取
        database_specific = item.get("database_specific", {})
        raw_sev = (database_specific.get("severity") or "").upper()

        if cvss_score is None:
            if raw_sev == "CRITICAL":
                cvss_score = 9.5
            elif raw_sev == "HIGH":
                cvss_score = 8.0
            elif raw_sev in ("MODERATE", "MEDIUM"):
                cvss_score = 5.5
            elif raw_sev == "LOW":
                cvss_score = 2.5

        # 确定最终 Severity 枚举
        if (cvss_score is not None and cvss_score >= 9.0) or raw_sev == "CRITICAL":
            severity = Severity.CRITICAL
        elif (cvss_score is not None and cvss_score >= 7.0) or raw_sev == "HIGH":
            severity = Severity.HIGH
        elif (cvss_score is not None and cvss_score >= 4.0) or raw_sev in ("MODERATE", "MEDIUM"):
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # 提取修复版本
        fixed_versions: List[str] = []
        affected = item.get("affected", [])
        for aff in affected:
            ranges = aff.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                for ev in events:
                    if "fixed" in ev:
                        fixed_versions.append(ev["fixed"])

        # 参考链接
        source_url = f"https://osv.dev/vulnerability/{advisory_id}"
        refs = item.get("references", [])
        if refs and isinstance(refs, list):
            source_url = refs[0].get("url", source_url)

        return Vulnerability(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary or details[:120],
            details=details,
            cvss_score=cvss_score,
            severity=severity,
            fixed_versions=fixed_versions,
            source_url=source_url,
        )
