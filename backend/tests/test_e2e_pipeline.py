"""端到端完整扫描流水线测试 (E2E Pipeline Test)
"""
import pytest
from httpx import ASGITransport, AsyncClient
from backend.app.main import app
from backend.app.domain.enums import RiskLevel, ScanStatus
from backend.app.domain.models import Project, Scan
from backend.app.services.orchestrator import ScanOrchestrator
from backend.app.services.queue import ScanQueueManager


class NoVulnerabilityOSVClient:
    async def query_batch_vulnerabilities(self, queries):
        return ([[] for _ in queries], True)


@pytest.mark.asyncio
async def test_e2e_benign_fixture_scan():
    orchestrator = ScanOrchestrator()
    orchestrator.dep_analyzer.osv_client = NoVulnerabilityOSVClient()
    scan = Scan(target_url="local://fixtures/benign_image_tool")
    project = Project(canonical_url="local://fixtures/benign_image_tool", name="benign_tool")

    res_scan, res_artifact, res_score, res_findings, res_deps, _ = await orchestrator.execute_scan(scan, project)

    assert res_scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    assert res_score.safety_score >= 85
    assert len(res_findings) == 0


@pytest.mark.asyncio
async def test_e2e_suspicious_stealer_fixture_scan():
    orchestrator = ScanOrchestrator()
    orchestrator.dep_analyzer.osv_client = NoVulnerabilityOSVClient()
    scan = Scan(target_url="local://fixtures/suspicious_stealer")
    project = Project(canonical_url="local://fixtures/suspicious_stealer", name="suspicious_stealer")

    res_scan, res_artifact, res_score, res_findings, res_deps, _ = await orchestrator.execute_scan(scan, project)

    assert res_scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)
    assert len(res_findings) >= 2
    # Static references/capabilities are warnings, not a malware verdict.
    assert res_score.safety_score >= 70
    assert res_score.risk_level != RiskLevel.HIGH
    assert res_score.caps_applied == []


@pytest.mark.asyncio
async def test_completed_scan_is_fully_readable_after_memory_cache_is_cleared():
    """Simulate an application restart and verify every user-facing result."""
    orchestrator = ScanOrchestrator()
    orchestrator.dep_analyzer.osv_client = NoVulnerabilityOSVClient()
    scan = Scan(target_url="local://fixtures/suspicious_stealer")
    project = Project(canonical_url=scan.target_url, name="restart_recovery")
    res_scan, _, _, findings, _, _ = await orchestrator.execute_scan(scan, project)
    assert res_scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL)

    queue = ScanQueueManager.get_instance()
    for cache in (
        queue.scans_cache,
        queue.projects_cache,
        queue.findings_cache,
        queue.dependencies_cache,
        queue.scores_cache,
        queue.artifacts_cache,
    ):
        cache.clear()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        summary = await client.get(f"/api/v1/scans/{scan.id}")
        assert summary.status_code == 200
        assert summary.json()["findings_count"] == len(findings)
        assert summary.json()["languages"] == ["python"]

        findings_response = await client.get(f"/api/v1/scans/{scan.id}/findings")
        assert findings_response.status_code == 200
        assert findings_response.json()["total"] == len(findings)

        dependencies = await client.get(f"/api/v1/scans/{scan.id}/dependencies")
        assert dependencies.status_code == 200

        score = await client.get(f"/api/v1/scans/{scan.id}/score")
        assert score.status_code == 200

        analysis = await client.get(f"/api/v1/scans/{scan.id}/analysis")
        assert analysis.status_code == 200
        assert analysis.json()["dynamic_analysis"]["executed_target_code"] is False

        report_meta = await client.get(f"/api/v1/scans/{scan.id}/report")
        assert report_meta.status_code == 200
        report_json = await client.get(f"/api/v1/scans/{scan.id}/report.json")
        assert report_json.status_code == 200

        history = await client.get("/api/v1/scans")
        assert history.status_code == 200
        assert any(item["scan_id"] == scan.id for item in history.json()["items"])
