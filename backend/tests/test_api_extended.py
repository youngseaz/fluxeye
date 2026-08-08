"""API 集成测试补充 — 覆盖缺失的端点（DNS / System / Packets / Geo / Pcap 下载）。

复用 test_api.py 的 client fixture（临时 SQLite 存储）。
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient

from app.main import app
from app.models.schemas import FlowRecord
from app.storage.deps import get_storage

from tests.test_api import client  # noqa: F401  (复用 client fixture)
from tests.test_protocols import (
    build_tcp_packet,
    build_http_get,
    build_udp_packet,
    build_dns_query,
    write_pcap,
)


def _get_store():
    """获取当前测试存储实例。"""
    return app.dependency_overrides[get_storage]()


async def _seed_dns_flows(store):
    """预填充 DNS 流。"""
    now = datetime.now(timezone.utc)
    flows = []
    for i in range(6):
        domain = f"www.dns{i % 2}.com"
        flows.append(FlowRecord(
            timestamp=now - timedelta(minutes=i * 2),
            src_ip=f"10.0.0.{i % 3 + 1}",
            dst_ip="8.8.8.8",
            src_port=40000 + i,
            dst_port=53,
            l4_proto="udp",
            l7_proto="dns",
            bytes_sent=50,
            bytes_recv=120,
            packets_sent=1,
            packets_recv=1,
            l7_meta=f"DNS 请求: {domain} (A) | DNS 响应: {domain} -> 1.2.3.4 (A)",
            duration_ms=20,
            dst_host=domain,
        ))
    await store.write_flows_batch(flows)


@pytest.mark.asyncio
class TestDNSAPIEndpoints:
    """DNS 仪表盘 API 端点测试。"""

    async def test_dns_overview(self, client: AsyncClient):
        await _seed_dns_flows(_get_store())
        resp = await client.get("/api/v1/traffic/dns/overview", params={"time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_queries"] == 6
        assert data["distinct_domains"] == 2
        assert data["distinct_clients"] == 3
        assert data["total_bytes"] > 0

    async def test_dns_top_domains(self, client: AsyncClient):
        await _seed_dns_flows(_get_store())
        resp = await client.get("/api/v1/traffic/dns/top-domains", params={"limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert all(d["host"].startswith("www.dns") for d in data)
        assert all(d["query_count"] > 0 for d in data)

    async def test_dns_top_clients(self, client: AsyncClient):
        await _seed_dns_flows(_get_store())
        resp = await client.get("/api/v1/traffic/dns/top-clients", params={"limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        assert all(c["src_ip"].startswith("10.0.0.") for c in data)

    async def test_dns_timeseries(self, client: AsyncClient):
        await _seed_dns_flows(_get_store())
        resp = await client.get("/api/v1/traffic/dns/timeseries", params={"interval": "60s", "time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert all(p["query_count"] >= 0 for p in data)

    async def test_dns_queries(self, client: AsyncClient):
        await _seed_dns_flows(_get_store())
        resp = await client.get("/api/v1/traffic/dns/queries", params={"limit": 50, "time_range": "1h"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 6
        assert all(q["domain"].startswith("www.dns") for q in data)
        # request_info / response_info 已剥离前缀
        assert all("->" in (q["response_info"] or "") for q in data)

    async def test_dns_queries_filter_domain(self, client: AsyncClient):
        await _seed_dns_flows(_get_store())
        resp = await client.get("/api/v1/traffic/dns/queries", params={"domain": "dns0"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 0
        assert all("dns0" in q["domain"] for q in data)

    async def test_dns_endpoints_empty(self, client: AsyncClient):
        """空库时 DNS 端点应返回空但不报错。"""
        assert (await client.get("/api/v1/traffic/dns/overview")).json()["total_queries"] == 0
        assert (await client.get("/api/v1/traffic/dns/top-domains")).json() == []
        assert (await client.get("/api/v1/traffic/dns/top-clients")).json() == []
        assert (await client.get("/api/v1/traffic/dns/queries")).json() == []


@pytest.mark.asyncio
class TestSystemStorageEndpoints:
    """系统存储/配置端点测试。"""

    async def test_system_storage(self, client: AsyncClient):
        resp = await client.get("/api/v1/system/storage")
        assert resp.status_code == 200
        data = resp.json()
        assert "disk_total" in data
        assert "disk_free" in data
        assert "pcap_dir" in data
        assert "pcap_files" in data

    async def test_pcap_config_get(self, client: AsyncClient):
        resp = await client.get("/api/v1/system/pcap/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "enabled" in data
        assert "storage_threshold_percent" in data
        assert "exclude_categories" in data
        assert "exclude_protocols" in data

    async def test_pcap_config_post_valid(self, client: AsyncClient):
        from app.config import settings
        # 读取当前值以便恢复
        orig_enabled = settings.collector.pcap_output.enabled
        orig_threshold = settings.collector.pcap_output.storage_threshold_percent
        orig_cats = list(settings.collector.pcap_output.exclude_categories)
        orig_protos = list(settings.collector.pcap_output.exclude_protocols)
        try:
            resp = await client.post("/api/v1/system/pcap/config",
                                     json={"enabled": True, "storage_threshold_percent": 70,
                                           "exclude_categories": ["Video", "Download"],
                                           "exclude_protocols": ["BitTorrent", "quic"]})
            assert resp.status_code == 200
            data = resp.json()
            assert data["success"] is True
            assert data["storage_threshold_percent"] == 70
            # 验证已写入 settings（小写归一化 + 排序）
            assert settings.collector.pcap_output.storage_threshold_percent == 70
            assert "video" in settings.collector.pcap_output.exclude_categories
            assert "download" in settings.collector.pcap_output.exclude_categories
            assert "bittorrent" in settings.collector.pcap_output.exclude_protocols
        finally:
            settings.collector.pcap_output.enabled = orig_enabled
            settings.collector.pcap_output.storage_threshold_percent = orig_threshold
            settings.collector.pcap_output.exclude_categories = orig_cats
            settings.collector.pcap_output.exclude_protocols = orig_protos

    async def test_pcap_config_post_exclude_empty(self, client: AsyncClient):
        """空排除列表应被接受（不排除任何流量）。"""
        from app.config import settings
        orig_cats = list(settings.collector.pcap_output.exclude_categories)
        orig_protos = list(settings.collector.pcap_output.exclude_protocols)
        try:
            resp = await client.post("/api/v1/system/pcap/config",
                                     json={"enabled": True, "storage_threshold_percent": 90,
                                           "exclude_categories": [], "exclude_protocols": []})
            assert resp.status_code == 200
            assert resp.json()["success"] is True
        finally:
            settings.collector.pcap_output.exclude_categories = orig_cats
            settings.collector.pcap_output.exclude_protocols = orig_protos

    async def test_pcap_config_post_invalid_threshold(self, client: AsyncClient):
        resp = await client.post("/api/v1/system/pcap/config",
                                 json={"enabled": True, "storage_threshold_percent": 5})
        assert resp.status_code == 400  # 阈值必须在 10-99

    async def test_pcap_cleanup_dir_not_found(self, client: AsyncClient):
        """pcap 目录不存在时返回 404。"""
        from app.api import system as system_api
        import tempfile
        orig = None
        import pathlib
        tmp = pathlib.Path(tempfile.mkdtemp()) / "no_such_cache_dir"
        try:
            orig = None
            # 直接 monkeypatch settings 指向不存在的目录
            from app.config import settings
            orig = settings.collector.pcap_output.dir
            settings.collector.pcap_output.dir = str(tmp)
            resp = await client.post("/api/v1/system/pcap/cleanup")
            assert resp.status_code == 404
        finally:
            if orig is not None:
                from app.config import settings
                settings.collector.pcap_output.dir = orig


@pytest.mark.asyncio
class TestPacketsEndpoints:
    """报文提取/流重组端点测试。"""

    async def test_flow_packets_flow_not_found(self, client: AsyncClient):
        resp = await client.get("/api/v1/traffic/flows/99999/packets")
        assert resp.status_code == 404

    async def test_flow_packets_pcap_missing(self, client: AsyncClient):
        store = _get_store()
        await store.write_flow(FlowRecord(
            timestamp=datetime.now(timezone.utc),
            src_ip="192.0.2.30", dst_ip="93.184.216.34",
            src_port=53001, dst_port=80, l4_proto="tcp", l7_proto="http",
            bytes_sent=100, bytes_recv=0, packets_sent=1, packets_recv=0,
            l7_meta="", duration_ms=10, pcap_file="/nonexistent/x.pcap",
        ))
        resp = await client.get("/api/v1/traffic/flows/1/packets")
        assert resp.status_code == 404  # pcap 文件不存在

    async def test_flow_packets_success(self, client: AsyncClient, tmp_path):
        """写入含真实 pcap 的流，提取报文应成功。"""
        # 生成 pcap：HTTP 请求
        packets = [
            build_tcp_packet("192.0.2.30", "93.184.216.34", 53001, 80,
                             build_http_get("www.packet-test.com")),
            build_udp_packet("192.0.2.30", "8.8.8.8", 53002, 53,
                             build_dns_query("www.packet-test.com")),
        ]
        pcap = tmp_path / "flows.pcap"
        write_pcap(str(pcap), packets)

        store = _get_store()
        flow_id = await store.write_flow(FlowRecord(
            timestamp=datetime.now(timezone.utc),
            src_ip="192.0.2.30", dst_ip="93.184.216.34",
            src_port=53001, dst_port=80, l4_proto="tcp", l7_proto="http",
            bytes_sent=100, bytes_recv=0, packets_sent=1, packets_recv=0,
            l7_meta="", duration_ms=10, pcap_file=str(pcap),
        ))
        resp = await client.get(f"/api/v1/traffic/flows/{flow_id}/packets")
        assert resp.status_code == 200
        data = resp.json()
        assert data["src_ip"] == "192.0.2.30"
        assert data["l4_proto"] == "tcp"
        assert data["total"] >= 1
        assert data["pcap_file"] == str(pcap)

    async def test_flow_stream_unsupported_proto(self, client: AsyncClient):
        store = _get_store()
        await store.write_flow(FlowRecord(
            timestamp=datetime.now(timezone.utc),
            src_ip="192.0.2.31", dst_ip="203.0.113.9",
            src_port=53003, dst_port=9999, l4_proto="icmp", l7_proto="unknown",
            bytes_sent=10, bytes_recv=0, packets_sent=1, packets_recv=0,
            l7_meta="", duration_ms=5, pcap_file="/nonexistent/x.pcap",
        ))
        resp = await client.get("/api/v1/traffic/flows/1/stream")
        assert resp.status_code == 400  # 仅支持 TCP/UDP/SCTP

    async def test_flow_stream_pcap_missing(self, client: AsyncClient):
        store = _get_store()
        await store.write_flow(FlowRecord(
            timestamp=datetime.now(timezone.utc),
            src_ip="192.0.2.32", dst_ip="93.184.216.34",
            src_port=53004, dst_port=80, l4_proto="tcp", l7_proto="http",
            bytes_sent=100, bytes_recv=0, packets_sent=1, packets_recv=0,
            l7_meta="", duration_ms=10, pcap_file="/nonexistent/x.pcap",
        ))
        resp = await client.get("/api/v1/traffic/flows/1/stream")
        assert resp.status_code == 404


@pytest.mark.asyncio
class TestGeoConfigEndpoints:
    """GeoIP 配置/数据库端点测试。"""

    async def test_geo_config_get(self, client: AsyncClient):
        resp = await client.get("/api/v1/geo/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "account_id" in data
        assert "license_key" in data

    async def test_geo_databases_list(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.api import geo as geo_api
        # 指向临时空目录
        empty = tmp_path / "empty_geo"
        empty.mkdir()
        monkeypatch.setattr(geo_api, "_get_db_dir", lambda: empty)
        resp = await client.get("/api/v1/geo/databases")
        assert resp.status_code == 200
        data = resp.json()
        assert data["files"] == []

    async def test_geo_upload_bad_extension(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.api import geo as geo_api
        monkeypatch.setattr(geo_api, "_get_db_dir", lambda: tmp_path)
        resp = await client.post(
            "/api/v1/geo/databases/upload",
            files={"file": ("evil.exe", b"data", "application/octet-stream")},
        )
        assert resp.status_code == 400  # 仅支持 .mmdb / .tar.gz

    async def test_geo_upload_valid_and_delete(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.api import geo as geo_api
        db_dir = tmp_path / "geo_db"
        db_dir.mkdir()
        monkeypatch.setattr(geo_api, "_get_db_dir", lambda: db_dir)
        # 上传
        resp = await client.post(
            "/api/v1/geo/databases/upload",
            files={"file": ("GeoLite2-City.mmdb", b"\x00\x01fake-mmdb", "application/octet-stream")},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert (db_dir / "GeoLite2-City.mmdb").exists()
        # 列表应包含
        data = (await client.get("/api/v1/geo/databases")).json()
        assert any(f["name"] == "GeoLite2-City.mmdb" for f in data["files"])
        # 删除
        resp = await client.delete("/api/v1/geo/databases/GeoLite2-City.mmdb")
        assert resp.status_code == 200
        assert not (db_dir / "GeoLite2-City.mmdb").exists()


@pytest.mark.asyncio
class TestPcapFileDownloadDelete:
    """pcap 文件下载/删除端点测试（成功路径）。"""

    async def test_download_success(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.api import capture as capture_api
        # 构造一个假的 pcap 文件
        pcap_dir = tmp_path / "captures"
        pcap_dir.mkdir()
        pcap = pcap_dir / "sample.pcap"
        pcap.write_bytes(b"\x00" * 100)
        monkeypatch.setattr(capture_api, "_get_capture_dir", lambda: pcap_dir)
        resp = await client.get("/api/v1/capture/pcap-files/sample.pcap")
        assert resp.status_code == 200
        assert resp.content == b"\x00" * 100

    async def test_download_path_traversal(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.api import capture as capture_api
        pcap_dir = tmp_path / "captures"
        pcap_dir.mkdir()
        # 目录外的文件
        outside = tmp_path / "secret.txt"
        outside.write_text("secret")
        monkeypatch.setattr(capture_api, "_get_capture_dir", lambda: pcap_dir)
        resp = await client.get("/api/v1/capture/pcap-files/../secret.txt")
        assert resp.status_code in (403, 404)  # 路径穿越被拦截

    async def test_delete_success(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.api import capture as capture_api
        pcap_dir = tmp_path / "captures"
        pcap_dir.mkdir()
        pcap = pcap_dir / "to_delete.pcap"
        pcap.write_bytes(b"\x01" * 50)
        monkeypatch.setattr(capture_api, "_get_capture_dir", lambda: pcap_dir)
        resp = await client.delete("/api/v1/capture/pcap-files/to_delete.pcap")
        assert resp.status_code == 200
        assert not pcap.exists()

    async def test_pcap_list_success(self, client: AsyncClient, tmp_path, monkeypatch):
        from app.api import capture as capture_api
        pcap_dir = tmp_path / "captures"
        pcap_dir.mkdir()
        (pcap_dir / "a.pcap").write_bytes(b"\x01" * 10)
        monkeypatch.setattr(capture_api, "_get_capture_dir", lambda: pcap_dir)
        resp = await client.get("/api/v1/capture/pcap-files")
        assert resp.status_code == 200
        data = resp.json()
        assert any(f["name"] == "a.pcap" for f in data)


@pytest.mark.asyncio
class TestProfileDetailFound:
    """设备画像详情端点（命中场景）。"""

    async def test_profile_detail_found(self, client: AsyncClient):
        store = _get_store()
        now = datetime.now(timezone.utc)
        await store.write_flows_batch([
            FlowRecord(
                timestamp=now - timedelta(minutes=1),
                src_ip="10.99.0.5", src_mac="00:11:22:33:44:66",
                dst_ip="93.184.216.34", src_port=40001, dst_port=443,
                l4_proto="tcp", l7_proto="tls", bytes_sent=100, bytes_recv=200,
                packets_sent=2, packets_recv=3, l7_meta="", duration_ms=500,
                dst_host="api.profile-test.com", dst_country="US",
            ),
        ])
        resp = await client.get("/api/v1/traffic/profiles/10.99.0.5")
        assert resp.status_code == 200
        data = resp.json()
        assert data is not None
        assert data["ip"] == "10.99.0.5"
        assert data["mac"] == "00:11:22:33:44:66"
        assert data["flow_count"] >= 1
        assert data["bytes_sent"] >= 100
