"""API 集成测试补全 — 覆盖剩余端点与带数据验证。

覆盖：
  1. POST /geo/config（配置更新）
  2. GET /traffic/pcap-files/{filename}/info（pcap 文件信息）
  3. conversations 的 time_start / time_end 过滤
  4. 流量端点在「有数据」时的非空验证（overview/protocols/top-talkers/
     time-series/top-domains/app-stats/services/totals/profiles）
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient

from app.main import app
from app.models.schemas import FlowRecord
from app.storage.deps import get_storage

from tests.test_api import client  # noqa: F401  (复用 client fixture)


def _get_store():
    return app.dependency_overrides[get_storage]()


async def _seed_flows(store):
    """预填充多种协议的流数据。"""
    now = datetime.now(timezone.utc)
    flows = [
        FlowRecord(
            timestamp=now - timedelta(minutes=1),
            src_ip="10.0.0.1", src_mac="00:11:22:33:44:01",
            dst_ip="93.184.216.34", src_port=40001, dst_port=80,
            l4_proto="tcp", l7_proto="http", bytes_sent=5000, bytes_recv=20000,
            packets_sent=10, packets_recv=30, l7_meta="GET / HTTP/1.1",
            duration_ms=800, dst_host="www.http-test.com", dst_country="US",
        ),
        FlowRecord(
            timestamp=now - timedelta(minutes=3),
            src_ip="10.0.0.2", src_mac="00:11:22:33:44:02",
            dst_ip="203.0.113.9", src_port=40002, dst_port=443,
            l4_proto="tcp", l7_proto="tls", bytes_sent=3000, bytes_recv=6000,
            packets_sent=8, packets_recv=12, l7_meta="", duration_ms=1200,
            dst_host="api.tls-test.com", dst_country="CN",
        ),
        FlowRecord(
            timestamp=now - timedelta(minutes=5),
            src_ip="10.0.0.3", src_mac="00:11:22:33:44:03",
            dst_ip="8.8.8.8", src_port=40003, dst_port=53,
            l4_proto="udp", l7_proto="dns", bytes_sent=100, bytes_recv=300,
            packets_sent=2, packets_recv=2, l7_meta="DNS 请求: dns.test.com (A)",
            duration_ms=30, dst_host="dns.test.com", dst_country="US",
        ),
    ]
    await store.write_flows_batch(flows)


@pytest.mark.asyncio
class TestGeoConfigUpdate:
    """POST /geo/config 端点测试。"""

    async def test_update_config(self, client: AsyncClient):
        from app.config import settings
        orig_aid = settings.geoip.account_id
        orig_lk = settings.geoip.license_key
        try:
            resp = await client.post(
                "/api/v1/geo/config",
                json={"account_id": "12345", "license_key": "ABCDEF123456"},
            )
            assert resp.status_code == 200
            assert resp.json()["success"] is True
            assert settings.geoip.account_id == "12345"
            assert settings.geoip.license_key == "ABCDEF123456"
        finally:
            settings.geoip.account_id = orig_aid
            settings.geoip.license_key = orig_lk

    async def test_update_config_empty_body(self, client: AsyncClient):
        """空 body 应为 no-op 且返回成功。"""
        resp = await client.post("/api/v1/geo/config", json={})
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    async def test_config_get_after_update(self, client: AsyncClient):
        """更新后 GET /config 应反映脱敏的 license_key。"""
        from app.config import settings
        orig_aid = settings.geoip.account_id
        orig_lk = settings.geoip.license_key
        try:
            await client.post("/api/v1/geo/config",
                              json={"account_id": "9999", "license_key": "SECRETKEY12345"})
            resp = await client.get("/api/v1/geo/config")
            assert resp.status_code == 200
            data = resp.json()
            assert data["account_id"] == "9999"
            assert "SECRETKEY12345" not in data["license_key"]  # 已脱敏
            assert data["has_account"] is True
        finally:
            settings.geoip.account_id = orig_aid
            settings.geoip.license_key = orig_lk


@pytest.mark.asyncio
class TestPcapFileInfo:
    """GET /traffic/pcap-files/{filename}/info 端点测试。"""

    async def test_info_not_found(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/pcap-files/nonexistent.pcap/info")
        assert resp.status_code == 404

    async def test_info_success(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.config import settings
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        pcap = cache_dir / "sample.pcap"
        pcap.write_bytes(b"\x00" * 256)
        orig = settings.collector.pcap_output.dir
        try:
            settings.collector.pcap_output.dir = str(cache_dir)
            resp = await client.get("/api/v1/traffic/pcap-files/sample.pcap/info")
            assert resp.status_code == 200
            data = resp.json()
            assert data["filename"] == "sample.pcap"
            assert data["size_bytes"] == 256
            assert "modified" in data
        finally:
            settings.collector.pcap_output.dir = orig


@pytest.mark.asyncio
class TestConversationsTimeFilters:
    """conversations 时间范围过滤测试。"""

    async def test_time_start_filter(self, client: AsyncClient):
        await _seed_flows(_get_store())
        # 只查最近 2 分钟内的流（应只含 1 条）
        since = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        resp = await client.get("/api/v1/traffic/conversations",
                                params={"time_start": since})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        # 所有返回流的时间应 >= since
        for item in data["items"]:
            assert item["timestamp"] >= since

    async def test_time_end_filter(self, client: AsyncClient):
        await _seed_flows(_get_store())
        until = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        resp = await client.get("/api/v1/traffic/conversations",
                                params={"time_end": until})
        assert resp.status_code == 200
        data = resp.json()
        # 应排除最近 1 分钟的流（http），剩余 2 条
        assert data["total"] >= 2

    async def test_pagination(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/conversations",
                                params={"page": 1, "size": 2})
        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 1
        assert data["size"] == 2
        assert len(data["items"]) <= 2
        # 第 2 页
        resp2 = await client.get("/api/v1/traffic/conversations",
                                 params={"page": 2, "size": 2})
        assert resp2.status_code == 200
        assert resp2.json()["page"] == 2


@pytest.mark.asyncio
class TestTrafficEndpointsWithData:
    """流量端点在「有数据」时验证真实聚合结果。"""

    async def test_overview_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/overview", params={"time_range": "30m"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_bps"] > 0
        assert data["active_flows"] >= 3

    async def test_protocols_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/protocols", params={"time_range": "30m"})
        assert resp.status_code == 200
        data = resp.json()["protocols"]
        protos = {p["l7_proto"] for p in data}
        assert "http" in protos
        assert "tls" in protos
        assert "dns" in protos

    async def test_top_talkers_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/top-talkers", params={"time_range": "30m", "top": 10})
        assert resp.status_code == 200
        data = resp.json()["talkers"]
        assert len(data) > 0
        assert all(t["bytes_total"] > 0 for t in data)

    async def test_time_series_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/time-series",
                                params={"time_range": "30m", "interval": "10m"})
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert any(p["bps"] > 0 for p in data)

    async def test_top_domains_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/top-domains",
                                params={"time_range": "30m", "limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        hosts = {d["host"] for d in data}
        assert "www.http-test.com" in hosts

    async def test_app_stats_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/app-stats",
                                params={"time_range": "30m", "limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert any(a["protocol"] == "http" for a in data)

    async def test_services_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/services",
                                params={"time_range": "30m", "limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 0
        assert all(s["bytes_total"] > 0 for s in data)

    async def test_totals_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/totals", params={"time_range": "30m"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_flows"] >= 3
        assert data["total_bytes"] > 0
        assert len(data["by_protocol"]) >= 3

    async def test_profiles_with_data(self, client: AsyncClient):
        await _seed_flows(_get_store())
        resp = await client.get("/api/v1/traffic/profiles", params={"time_range": "30m"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 3
        assert len(data["devices"]) >= 3
        assert all(d["ip"].startswith("10.0.0.") for d in data["devices"])
