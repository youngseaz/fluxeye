"""SQLite 存储后端扩展测试 — 安全查询、域名、服务、设备画像。"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from app.config import SQLiteConfig
from app.models.schemas import FlowRecord
from app.storage.sqlite_store import SQLiteStore


async def store_with_risk_data():
    """预填充含风险数据的存储后端。"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    store = SQLiteStore(SQLiteConfig(path=path))
    await store.initialize()
    now = datetime.now(timezone.utc)

    flows = []
    for i in range(15):
        risk_score = 0
        risks = []
        if i < 5:
            risk_score = 50
            risks = [{"id": 5, "name": "Known Proto on Non Std Port", "severity": 2, "severity_name": "medium", "info": ""}]
        elif i < 10:
            risk_score = 150
            risks = [{"id": 6, "name": "TLS Self-Signed Certificate", "severity": 3, "severity_name": "severe", "info": ""}]

        flows.append(FlowRecord(
            timestamp=now - timedelta(minutes=i * 5),
            src_ip=f"10.0.0.{i % 3 + 1}",
            dst_ip=f"192.168.{i % 2 + 1}.{i + 1}",
            src_port=40000 + i, dst_port=443,
            l4_proto="tcp", l7_proto="tls" if i % 2 == 0 else "socks",
            bytes_sent=1000 * (i + 1), bytes_recv=500 * (i + 1),
            packets_sent=i + 1, packets_recv=i + 1,
            l7_meta=f"host{i}.example.com",
            l7_category="web" if i % 2 == 0 else "proxy",
            duration_ms=1000 * (i + 1),
            dst_host=f"service{i}.example.com",
            dst_country="US" if i % 2 == 0 else "CN",
            dst_city="San Jose" if i % 2 == 0 else "Beijing",
            risks=risks, risk_score=risk_score,
        ))
    await store.write_flows_batch(flows)
    return store, path


@pytest.mark.asyncio
class TestSecurityQueries:
    """安全态势查询测试。"""

    async def test_query_security_events_empty(self, sqlite_store: SQLiteStore):
        """空数据库应返回空列表。"""
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        events = await sqlite_store.query_security_events(since=since)
        assert isinstance(events, list)
        assert len(events) == 0

    async def test_query_security_overview_empty(self, sqlite_store: SQLiteStore):
        """空数据库概览应为零。"""
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        overview = await sqlite_store.query_security_overview(since=since)
        assert overview.total_events == 0
        assert overview.critical_count == 0

    async def test_query_security_events_with_data(self):
        """含风险数据的查询。"""
        store, path = await store_with_risk_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            events = await store.query_security_events(since=since)
            assert len(events) > 0
            for evt in events:
                assert evt.risk_score > 0
                assert len(evt.risks) > 0
                assert evt.risk_level in ("low", "medium", "high", "severe", "critical", "emergency", "")
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_security_overview_with_data(self):
        """安全概览统计。"""
        store, path = await store_with_risk_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            overview = await store.query_security_overview(since=since)
            assert overview.total_events > 0
            assert isinstance(overview.top_risks, list)
            assert isinstance(overview.by_severity, list)
            assert len(overview.by_severity) == 4
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_security_events_min_score(self):
        """最低风险分筛选。"""
        store, path = await store_with_risk_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            events = await store.query_security_events(since=since, min_score=100)
            for evt in events:
                assert evt.risk_score >= 100
        finally:
            await store.close()
            os.unlink(path)


@pytest.mark.asyncio
class TestDomainQueries:
    """域名统计查询测试。"""

    async def test_query_top_domains_empty(self, sqlite_store: SQLiteStore):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        domains = await sqlite_store.query_top_domains(since=since)
        assert isinstance(domains, list)
        assert len(domains) == 0

    async def test_query_top_domains_with_data(self):
        store, path = await store_with_risk_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            domains = await store.query_top_domains(since=since)
            assert len(domains) > 0
            for d in domains:
                assert d.host != ""
                assert d.bytes_total > 0
                assert d.flow_count > 0
                assert 0 <= d.percentage <= 100
        finally:
            await store.close()
            os.unlink(path)


@pytest.mark.asyncio
class TestAppStatsQueries:
    """应用统计查询测试。"""

    async def test_query_app_stats_empty(self, sqlite_store: SQLiteStore):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        stats = await sqlite_store.query_app_stats(since=since)
        assert isinstance(stats, list)
        assert len(stats) == 0

    async def test_query_app_stats_with_data(self):
        store, path = await store_with_risk_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            stats = await store.query_app_stats(since=since)
            assert len(stats) > 0
            total_pct = sum(s.percentage for s in stats)
            assert abs(total_pct - 100.0) < 0.01
        finally:
            await store.close()
            os.unlink(path)


@pytest.mark.asyncio
class TestServiceStatsQueries:
    """应用服务统计查询测试。"""

    async def test_query_services_stats_empty(self, sqlite_store: SQLiteStore):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        stats = await sqlite_store.query_services_stats(since=since)
        assert isinstance(stats, list)

    async def test_query_services_stats_with_data(self):
        store, path = await store_with_risk_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            stats = await store.query_services_stats(since=since)
            assert len(stats) > 0
            for s in stats:
                assert s.service != ""
                assert s.bytes_total > 0
                assert s.flow_count > 0
        finally:
            await store.close()
            os.unlink(path)


@pytest.mark.asyncio
class TestTrafficTotalsQueries:
    """流量总和统计查询测试。"""

    async def test_query_traffic_totals_empty(self, sqlite_store: SQLiteStore):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        totals = await sqlite_store.query_traffic_totals(since=since)
        assert totals.total_bytes == 0
        assert totals.total_packets == 0
        assert totals.total_flows == 0

    async def test_query_traffic_totals_with_data(self):
        store, path = await store_with_risk_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=2)
            totals = await store.query_traffic_totals(since=since)
            assert totals.total_bytes > 0
            assert totals.total_packets > 0
            assert totals.total_flows > 0
            assert len(totals.by_protocol) > 0
        finally:
            await store.close()
            os.unlink(path)


@pytest.mark.asyncio
class TestDeviceProfileQueries:
    """设备画像查询测试。"""

    async def test_query_device_profiles_empty(self, sqlite_store: SQLiteStore):
        result = await sqlite_store.query_device_profiles(since_ts=0)
        assert result.total == 0
        assert len(result.devices) == 0

    async def test_query_device_profiles_with_data(self):
        store, path = await store_with_risk_data()
        try:
            result = await store.query_device_profiles(since_ts=0)
            assert result.total > 0
            assert len(result.devices) > 0
            for dev in result.devices:
                assert dev.ip != ""
                assert dev.bytes_sent >= 0
                assert dev.bytes_recv >= 0
                assert dev.flow_count > 0
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_device_profile_detail(self):
        store, path = await store_with_risk_data()
        try:
            result = await store.query_device_profiles(since_ts=0)
            if result.devices:
                ip = result.devices[0].ip
                detail = await store.query_device_profile_detail(ip=ip, since_ts=0)
                assert detail is not None
                assert detail.ip == ip
                assert detail.flow_count > 0
                assert isinstance(detail.top_protocols, list)
                assert isinstance(detail.top_peers, list)
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_device_profile_sort_by_risk(self):
        store, path = await store_with_risk_data()
        try:
            result = await store.query_device_profiles(since_ts=0, sort_by="risk")
            if len(result.devices) > 1:
                scores = [d.risk_score for d in result.devices]
                assert scores == sorted(scores, reverse=True)
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_device_profile_sort_by_flows(self):
        store, path = await store_with_risk_data()
        try:
            result = await store.query_device_profiles(since_ts=0, sort_by="flows")
            if len(result.devices) > 1:
                flows = [d.flow_count for d in result.devices]
                assert flows == sorted(flows, reverse=True)
        finally:
            await store.close()
            os.unlink(path)


@pytest.mark.asyncio
class TestFlowRecordWithRisks:
    """含风险信息的流记录写入/读取测试。"""

    async def test_write_flow_with_risks(self, sqlite_store: SQLiteStore):
        """写入含风险的流。"""
        now = datetime.now(timezone.utc)
        flow = FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp",
            l7_proto="tls", bytes_sent=100, bytes_recv=200,
            packets_sent=1, packets_recv=2, l7_meta="", duration_ms=1000,
            risks=[{"id": 6, "name": "TLS Self-Signed Certificate", "severity": 3}],
            risk_score=150,
        )
        flow_id = await sqlite_store.write_flow(flow)
        assert flow_id > 0

    async def test_read_flow_with_risks(self, sqlite_store: SQLiteStore):
        """读取含风险的流。"""
        now = datetime.now(timezone.utc)
        flow = FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp",
            l7_proto="tls", bytes_sent=100, bytes_recv=200,
            packets_sent=1, packets_recv=2, l7_meta="", duration_ms=1000,
            risks=[{"id": 5, "name": "Known Non Std Port", "severity": 2}],
            risk_score=50,
        )
        await sqlite_store.write_flow(flow)
        fetched = await sqlite_store.query_flow_by_id(1)
        assert fetched is not None
        assert len(fetched.risks) == 1
        assert fetched.risk_score == 50

    async def test_cleanup_old_flows(self, sqlite_store: SQLiteStore):
        """清理旧流记录。"""
        now = datetime.now(timezone.utc)
        old = FlowRecord(
            timestamp=now - timedelta(days=30), src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp",
            l7_proto="tls", bytes_sent=100, bytes_recv=200,
            packets_sent=1, packets_recv=2, l7_meta="", duration_ms=1000,
        )
        new = FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp",
            l7_proto="tls", bytes_sent=100, bytes_recv=200,
            packets_sent=1, packets_recv=2, l7_meta="", duration_ms=1000,
        )
        await sqlite_store.write_flows_batch([old, new])
        deleted = await sqlite_store.cleanup_old_flows(retention_days=7)
        assert deleted >= 1
        # 新记录应保留
        overview = await sqlite_store.query_overview(time_range="1h")
        assert overview.active_flows >= 1


async def store_with_dns_data():
    """预填充 DNS 查询/响应流的存储后端。"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    store = SQLiteStore(SQLiteConfig(path=path))
    await store.initialize()
    now = datetime.now(timezone.utc)

    flows = []
    for i in range(10):
        domain = f"www.site{i % 3}.com"
        client = f"10.0.0.{i % 4 + 1}"
        flows.append(FlowRecord(
            timestamp=now - timedelta(minutes=i * 2),
            src_ip=client,
            dst_ip="8.8.8.8",
            src_port=40000 + i,
            dst_port=53,
            l4_proto="udp",
            l7_proto="dns",
            bytes_sent=50,
            bytes_recv=120,
            packets_sent=1,
            packets_recv=1,
            l7_meta=f"DNS 请求: {domain} (A) | DNS 响应: {domain} -> 1.2.3.{i % 3 + 1} (A)",
            duration_ms=30,
            dst_host=domain,
        ))
    await store.write_flows_batch(flows)
    return store, path


@pytest.mark.asyncio
class TestDNSQueries:
    """DNS 统计查询测试。"""

    async def test_query_dns_overview_empty(self, sqlite_store: SQLiteStore):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        overview = await sqlite_store.query_dns_overview(since=since)
        assert overview.total_queries == 0
        assert overview.total_bytes == 0
        assert overview.distinct_domains == 0
        assert overview.distinct_clients == 0

    async def test_query_dns_overview_with_data(self):
        store, path = await store_with_dns_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            overview = await store.query_dns_overview(since=since)
            assert overview.total_queries == 10
            assert overview.distinct_domains == 3
            assert overview.distinct_clients == 4
            assert overview.total_bytes > 0
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_dns_top_domains(self):
        store, path = await store_with_dns_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            domains = await store.query_dns_top_domains(since=since, limit=5)
            assert len(domains) == 3
            assert domains[0].host in {"www.site0.com", "www.site1.com", "www.site2.com"}
            assert domains[0].query_count > 0
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_dns_top_clients(self):
        store, path = await store_with_dns_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            clients = await store.query_dns_top_clients(since=since, limit=5)
            assert len(clients) == 4
            assert clients[0].src_ip.startswith("10.0.0.")
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_dns_timeseries(self):
        store, path = await store_with_dns_data()
        try:
            now = datetime.now(timezone.utc)
            since = now - timedelta(minutes=30)
            points = await store.query_dns_timeseries(since=since, span_seconds=1800, bucket_seconds=300)
            assert len(points) > 0
            assert all(p.query_count >= 0 for p in points)
            total_queries = sum(p.query_count for p in points)
            assert total_queries >= 10
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_dns_details(self):
        store, path = await store_with_dns_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            details = await store.query_dns_details(since=since, limit=100)
            assert len(details) == 10
            detail = details[0]
            assert detail.domain.startswith("www.site")
            assert detail.client_ip.startswith("10.0.0.")
            # request_info/response_info 已剥离 "DNS 请求:"/"DNS 响应:" 前缀
            assert "(A)" in (detail.request_info or "")
            assert detail.domain in (detail.request_info or "")
            assert "->" in (detail.response_info or "")
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_dns_details_filter(self):
        store, path = await store_with_dns_data()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=1)
            details = await store.query_dns_details(since=since, limit=100, domain="site0")
            assert len(details) > 0
            assert all("site0" in d.domain for d in details)
        finally:
            await store.close()
            os.unlink(path)

    async def test_query_dns_details_empty(self, sqlite_store: SQLiteStore):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        details = await sqlite_store.query_dns_details(since=since, limit=100)
        assert details == []

    async def test_split_dns_req_res(self):
        """_split_dns_req_res 辅助函数。"""
        from app.storage.sqlite_store import _split_dns_req_res
        req, resp = _split_dns_req_res(
            "DNS 请求: www.a.com (A) | DNS 响应: www.a.com -> 1.2.3.4 (A)"
        )
        assert "www.a.com (A)" in req
        assert "1.2.3.4" in resp
        # 无响应内容时
        req2, resp2 = _split_dns_req_res("DNS 请求: www.a.com (A)")
        assert "www.a.com" in req2
        assert resp2 == ""
