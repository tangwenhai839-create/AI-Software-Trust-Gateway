"""FastAPI 控制平面端点单元测试
"""
import pytest
from httpx import ASGITransport, AsyncClient
from backend.app.main import app


@pytest.mark.asyncio
async def test_health_and_capabilities_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp_live = await client.get("/api/v1/health/live")
        assert resp_live.status_code == 200
        assert resp_live.json()["status"] == "alive"

        resp_caps = await client.get("/api/v1/capabilities")
        assert resp_caps.status_code == 200
        data = resp_caps.json()
        assert "astg_ast_python" in data["scanners"]
        assert data["mode"] == "mvp-static-v1"


@pytest.mark.asyncio
async def test_create_and_query_scan():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. 提交扫描
        payload = {
            "source": {"type": "local", "url": "local://fixtures/benign_image_tool", "ref": "main"},
            "profile": "mvp-static-v1",
            "ai": {"enabled": False}
        }
        resp = await client.post("/api/v1/scans", json=payload)
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]
        assert scan_id is not None

        # 2. 查询状态
        resp_status = await client.get(f"/api/v1/scans/{scan_id}")
        assert resp_status.status_code == 200
        assert resp_status.json()["scan_id"] == scan_id
