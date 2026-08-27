"""AI Software Trust Gateway - OSV 漏洞数据库客户端 (OSV API Client with Batch, Real CVSS & Fallback)
"""
import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote
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
        self.detail_api_base = self.api_url.rsplit("/", 1)[0] + "/vulns"
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
                    detail_cache = await self._fetch_missing_details(client, raw_results)
                    for idx, res in enumerate(raw_results):
                        vulns_data = res.get("vulns", [])
                        parsed_vulns = [
                            self._parse_osv_item(detail_cache.get(v.get("id"), v))
                            for v in vulns_data
                        ]
                        results[idx] = self._deduplicate_vulnerabilities(parsed_vulns)
                    return results, True
                else:
                    logger.warning("OSV API 请求返回非 200", status=resp.status_code)
                    return results, False
        except Exception as e:
            logger.warning("OSV 漏洞数据库查询离线或超时，降级为离线依赖审查", error=str(e))
            return results, False

    async def _fetch_missing_details(
        self,
        client: httpx.AsyncClient,
        raw_results: List[Dict[str, Any]],
    ) -> Dict[str, Dict[str, Any]]:
        """Enrich querybatch's minimal ID records with OSV vulnerability details."""
        minimal_items: Dict[str, Dict[str, Any]] = {}
        for result in raw_results:
            for item in result.get("vulns", []):
                advisory_id = item.get("id")
                if advisory_id:
                    minimal_items.setdefault(advisory_id, item)

        semaphore = asyncio.Semaphore(8)

        async def fetch_one(advisory_id: str, fallback: Dict[str, Any]):
            if fallback.get("summary") and fallback.get("affected"):
                return advisory_id, fallback
            try:
                async with semaphore:
                    response = await client.get(
                        f"{self.detail_api_base}/{quote(advisory_id, safe='')}",
                    )
                if response.status_code == 200:
                    return advisory_id, {**fallback, **response.json()}
            except Exception as exc:
                logger.debug("OSV 漏洞详情查询失败，保留基础记录", advisory_id=advisory_id, error=str(exc))
            return advisory_id, fallback

        enriched = await asyncio.gather(
            *(fetch_one(advisory_id, item) for advisory_id, item in minimal_items.items())
        )
        return dict(enriched)

    @staticmethod
    def _deduplicate_vulnerabilities(vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Collapse OSV records that describe the same issue through aliases."""
        deduplicated: List[Vulnerability] = []
        seen_identifiers: set[str] = set()
        for vulnerability in vulnerabilities:
            identifiers = {vulnerability.advisory_id, *vulnerability.aliases}
            if identifiers & seen_identifiers:
                continue
            deduplicated.append(vulnerability)
            seen_identifiers.update(identifier for identifier in identifiers if identifier)
        return deduplicated

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
