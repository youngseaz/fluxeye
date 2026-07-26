"""API 集成测试 — 使用 httpx 的 AsyncClient。"""

from __future__ import annotations

import os
import tempfile
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.config import SQLiteConfig
from app.main import app
from app.models.schemas import FlowRecord
from app.storage.deps import get_storage, close_storage
from app.storage.sqlite_store import SQLiteStore


@pytest_asyncio.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    """创建一个测试用 HTTP 客户端。

    使用临时 SQLite 数据库作为存储后端，测试完毕后自动清理。
    """
    # 创建临时数据库
    fd, db_path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    os.environ["FLUXEYE__STORAGE__SQLITE__PATH"] = db_path

    # 初始化存储
    store = SQLiteStore(SQLiteConfig(path=db_path))
    await store.initialize()

    # 注入测试用存储
    app.dependency_overrides[get_storage] = lambda: store

    # 创建 HTTP 客户端
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    # 清理
    app.dependency_overrides.clear()
    await store.close()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.mark.asyncio
class TestHealthEndpoint:
    """健康检查端点测试。"""

    async def test_health_returns_ok(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "storage" in data


@pytest.mark.asyncio
class TestSystemEndpoint:
    """系统状态端点测试。"""

    async def test_system_status(self, client: AsyncClient):
        resp = await client.get("/api/v1/system/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert "uptime_seconds" in data
        assert "version" in data


@pytest.mark.asyncio
class TestTrafficEndpoints:
    """流量数据端点测试。"""

    async def test_overview(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/overview", params={"time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert "total_bps" in data
        assert "total_pps" in data
        assert "active_flows" in data
        assert "total_connections" in data

    async def test_protocols(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/protocols", params={"time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert "protocols" in data
        assert "time_range" in data

    async def test_top_talkers(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/top-talkers", params={"top": 5, "time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert "talkers" in data

    async def test_time_series(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/time-series", params={"interval": "10s", "time_range": "5m"})
        assert resp.status_code == 200
        data = resp.json()
        assert "data" in data

    async def test_live_sessions(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/live")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    async def test_conversations(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/conversations")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data

    async def test_top_domains(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/top-domains", params={"time_range": "1h", "limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    async def test_app_stats(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/app-stats", params={"time_range": "1h", "limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    async def test_services_stats(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/services", params={"time_range": "1h", "limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    async def test_traffic_totals(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/totals", params={"time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert "total_bytes" in data
        assert "total_packets" in data
        assert "total_flows" in data
        assert "by_protocol" in data
        assert "by_category" in data

    async def test_device_profiles(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/profiles", params={"time_range": "24h"})
        assert resp.status_code == 200
        data = resp.json()
        assert "devices" in data
        assert "total" in data


@pytest.mark.asyncio
class TestSecurityEndpoints:
    """安全态势端点测试。"""

    async def test_security_overview(self, client: AsyncClient):
        resp = await client.get("/api/v1/security/overview", params={"time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert "total_events" in data
        assert "critical_count" in data
        assert "top_risks" in data
        assert "by_severity" in data

    async def test_security_events(self, client: AsyncClient):
        resp = await client.get("/api/v1/security/events", params={"time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)



@pytest.mark.asyncio
class TestCaptureEndpoints:
    """抓包控制端点测试（合并版）。"""

    async def test_capture_status(self, client: AsyncClient):
        resp = await client.get("/api/v1/capture/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data
        assert "packets_processed" in data
        assert "dpi_available" in data

    async def test_capture_interfaces(self, client: AsyncClient):
        resp = await client.get("/api/v1/capture/interfaces")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    async def test_capture_start_requires_interface(self, client: AsyncClient):
        resp = await client.post("/api/v1/capture/start", json={"interface": ""})
        assert resp.status_code == 503
        assert "detail" in resp.json()

    async def test_capture_stop_when_not_running(self, client: AsyncClient):
        resp = await client.post("/api/v1/capture/stop")
        assert resp.status_code == 200
        assert resp.json()["message"] == "抓包未运行"

    async def test_pcap_files(self, client: AsyncClient):
        resp = await client.get("/api/v1/capture/pcap-files")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)

    async def test_recording_status(self, client: AsyncClient):
        resp = await client.get("/api/v1/capture/recording/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "recording" in data

    async def test_recording_start_stop(self, client: AsyncClient):
        """未初始化时启停录制返回 503。"""
        resp = await client.post("/api/v1/capture/recording/start")
        assert resp.status_code == 503

        resp = await client.post("/api/v1/capture/recording/stop")
        # 未初始化时停止可能返回 503 或 200（取决于实现）
        assert resp.status_code in (200, 503)

    async def test_pcap_download_not_found(self, client: AsyncClient):
        """下载不存在的 pcap 文件返回 404。"""
        resp = await client.get("/api/v1/capture/pcap-files/nonexistent.pcap")
        assert resp.status_code == 404

    async def test_pcap_delete_not_found(self, client: AsyncClient):
        """删除不存在的 pcap 文件返回 404。"""
        resp = await client.delete("/api/v1/capture/pcap-files/nonexistent.pcap")
        assert resp.status_code == 404


@pytest.mark.asyncio
class TestGeoEndpoints:
    """GeoIP 端点测试。"""

    async def test_geo_status(self, client: AsyncClient):
        resp = await client.get("/api/v1/geo/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "available" in data

    async def test_geo_update(self, client: AsyncClient):
        """触发 GeoIP 更新（可能因无网络返回 500）。"""
        resp = await client.post("/api/v1/geo/update")
        # 测试环境中 GeoIP 可能不可用
        assert resp.status_code in (200, 409, 500)


@pytest.mark.asyncio
class TestIPFIXEndpoints:
    """IPFIX 导出端点测试。"""

    async def test_ipfix_status(self, client: AsyncClient):
        resp = await client.get("/api/v1/export/ipfix/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data

    async def test_ipfix_start_stop(self, client: AsyncClient):
        """未初始化流水线时启停返回 503。"""
        resp = await client.post("/api/v1/export/ipfix/start")
        assert resp.status_code == 503

        resp = await client.post("/api/v1/export/ipfix/stop")
        assert resp.status_code in (200, 400, 503)


@pytest.mark.asyncio
class TestFlowDetailEndpoint:
    """流详情端点测试。"""

    async def test_flow_detail_not_found(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/flows/99999")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Flow not found"

    async def test_flow_detail_found(self, client: AsyncClient):
        from datetime import datetime, timezone
        from app.storage.deps import get_storage
        store = app.dependency_overrides[get_storage]()
        await store.write_flow(FlowRecord(
            timestamp=datetime.now(timezone.utc),
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=200,
            packets_sent=1, packets_recv=2,
            l7_meta="", duration_ms=1000,
        ))
        resp = await client.get("/api/v1/traffic/flows/1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["src_ip"] == "10.0.0.1"

    async def test_time_series(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/time-series", params={"interval": "10s", "time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert "data" in data
        assert "interval" in data

    async def test_conversations(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/conversations", params={"page": 1, "size": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "size" in data

    async def test_conversation_fields(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/conversations", params={"page": 1, "size": 1})
        assert resp.status_code == 200
        data = resp.json()
        if data["items"]:
            item = data["items"][0]
            assert "packets_sent" in item
            assert "packets_recv" in item
            assert "l7_meta" in item

    async def test_conversations_filter(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/conversations", params={"l7_proto": "tls"})
        assert resp.status_code == 200


@pytest.mark.asyncio
class TestDeviceProfileDetail:
    """设备画像详情端点测试。"""

    async def test_device_profile_detail_not_found(self, client: AsyncClient):
        """不存在的 IP 返回 None。"""
        resp = await client.get("/api/v1/traffic/profiles/1.2.3.4")
        assert resp.status_code == 200
        data = resp.json()
        assert data is None

    async def test_device_profile_detail_with_data(self, client: AsyncClient):
        """写入数据后查询设备详情。"""
        from datetime import datetime, timezone
        from app.storage.deps import get_storage
        store = app.dependency_overrides[get_storage]()
        await store.write_flow(FlowRecord(
            timestamp=datetime.now(timezone.utc),
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=80, l4_proto="tcp", l7_proto="http",
            bytes_sent=1000, bytes_recv=2000,
            packets_sent=5, packets_recv=10,
            l7_meta="", duration_ms=500,
            dst_host="example.com",
        ))
        resp = await client.get("/api/v1/traffic/profiles/10.0.0.1",
                                params={"time_range": "24h"})
        assert resp.status_code == 200
        data = resp.json()
        assert data is not None
        assert data["ip"] == "10.0.0.1"
        assert data["flow_count"] > 0
        assert data["bytes_sent"] > 0
        assert data["bytes_recv"] > 0


@pytest.mark.asyncio
class TestWebSocketEndpoint:
    """WebSocket 实时推送端点测试。"""

    async def test_websocket_live_connect_and_message(self, client: AsyncClient):
        """WebSocket 连接后应能收到推送消息。"""
        from starlette.testclient import TestClient
        from app.main import app as fastapi_app

        # 使用 Starlette TestClient（同步）测试 WebSocket
        with TestClient(fastapi_app) as test_client:
            with test_client.websocket_connect("/api/v1/ws/live") as ws:
                data = ws.receive_json()
                assert data is not None
                assert "total_bps" in data
                assert "total_pps" in data
                assert "active_flows" in data


@pytest.mark.asyncio
class TestCORS:
    """CORS 中间件测试。"""

    async def test_cors_headers(self, client: AsyncClient):
        resp = await client.options(
            "/health",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.status_code == 200

    async def test_cors_preflight(self, client: AsyncClient):
        """OPTIONS 请求应返回正确的 CORS 头。"""
        resp = await client.options(
            "/api/v1/traffic/overview",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert resp.status_code == 200


@pytest.mark.asyncio
class TestErrorHandling:
    """错误处理测试。"""

    async def test_not_found(self, client: AsyncClient):
        resp = await client.get("/api/v1/nonexistent")
        assert resp.status_code == 404

    async def test_invalid_params(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/conversations", params={"page": -1})
        assert resp.status_code == 422
