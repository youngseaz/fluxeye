"""InfluxDBStore 单元测试 — 使用 fake 客户端验证 Point 构造、Flux 生成、注入安全。"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.config import InfluxDBConfig
from app.models.schemas import FlowRecord
from app.storage.influxdb_store import InfluxDBStore


class FakeRecord:
    def __init__(self, values: dict):
        self.values = values

    def get_value(self):
        return self.values.get("_value")

    def get_field(self):
        return self.values.get("_field")


class FakeTable:
    def __init__(self, records):
        self.records = records


class FakeQueryAPI:
    def __init__(self, tables=None, by_query=None):
        self.tables = tables or []
        self.by_query = by_query or {}
        self.last_query = ""

    def query(self, query):
        self.last_query = query
        for key, t in self.by_query.items():
            if key in query:
                return t
        return self.tables


class FakeWriteAPI:
    def __init__(self):
        self.points = []

    def write(self, bucket, org, record):
        self.points.extend(record)


class FakeClient:
    def __init__(self, tables=None, by_query=None):
        self._query_api = FakeQueryAPI(tables, by_query)
        self._write_api = FakeWriteAPI()

    def query_api(self):
        return self._query_api

    def write_api(self, **kwargs):
        return self._write_api

    def close(self):
        pass


def _store(tables=None, by_query=None) -> InfluxDBStore:
    store = InfluxDBStore(InfluxDBConfig())
    store._client = FakeClient(tables, by_query)
    store._available = True
    return store


def _flow(**over) -> FlowRecord:
    base = dict(
        timestamp=datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.1", dst_ip="93.184.216.34",
        src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
        bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2,
        l7_meta="", duration_ms=1000, dst_host="www.example.com",
        risks=[{"id": 1}], risk_score=50,
    )
    base.update(over)
    return FlowRecord(**base)


@pytest.mark.asyncio
class TestInfluxDBWrite:
    async def test_write_flow_creates_point(self):
        store = _store()
        fid = await store.write_flow(_flow())
        assert fid == 1
        pts = store._client._write_api.points
        assert len(pts) == 1
        p = pts[0]
        tags = dict(p._tags)
        fields = dict(p._fields)
        assert tags["src_ip"] == "10.0.0.1"
        assert tags["l7_proto"] == "tls"
        assert fields["bytes_sent"] == 100
        assert fields["risk_score"] == 50
        assert fields["flow_id"] == 1

    async def test_write_flows_batch(self):
        store = _store()
        n = await store.write_flows_batch([_flow(), _flow(src_ip="10.0.0.2")])
        assert n == 2
        assert len(store._client._write_api.points) == 2

    async def test_write_unavailable_returns_zero(self):
        store = InfluxDBStore(InfluxDBConfig())
        store._available = False
        assert await store.write_flow(_flow()) == 0
        assert await store.write_flows_batch([_flow()]) == 0


@pytest.mark.asyncio
class TestInfluxDBQuery:
    async def test_query_overview_scalar(self):
        # 按查询内容返回：bytes=8000, packets=100, flow 数=3
        scalar = lambda v: [FakeTable([FakeRecord({"_value": v})])]
        store = _store(by_query={
            "bytes_sent": scalar(8000.0),
            "packets_sent": scalar(100.0),
            "distinct": scalar(3.0),
        })
        ov = await store.query_overview(time_range="1m")
        assert ov.total_connections == 3
        assert ov.active_flows == 3
        assert ov.total_bps > 0
        assert ov.total_pps > 0

    async def test_query_conversations_maps_row(self):
        row_values = {
            "_time": datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
            "_field": "flow_id", "_value": 5,
            "flow_id": 5, "src_ip": "10.0.0.1", "dst_ip": "93.184.216.34",
            "src_port": "40000", "dst_port": "443",
            "l4_proto": "tcp", "l7_proto": "tls",
            "bytes_sent": 100, "bytes_recv": 200,
            "dst_host": "www.example.com", "l7_meta": "",
        }
        store = _store([FakeTable([FakeRecord(row_values)])])
        page = await store.query_conversations(l7_proto="tls")
        assert len(page.items) == 1
        c = page.items[0]
        assert c.src_ip == "10.0.0.1"
        assert c.l7_proto == "tls"
        # 过滤条件进入 Flux 且值被转义
        flux = store._client._query_api.last_query
        assert 'r.l7_proto == "tls"' in flux

    async def test_query_conversations_injection_safe(self):
        store = _store([])
        payload = 'x"; DROP MEASUREMENT flows; --'
        await store.query_conversations(l7_proto=payload)
        flux = store._client._query_api.last_query
        assert payload not in flux  # 原始载荷不应出现
        assert '\\"' in flux  # 引号被转义

    async def test_query_unavailable_returns_empty(self):
        store = InfluxDBStore(InfluxDBConfig())
        store._available = False
        assert (await store.query_overview()).total_connections == 0
        assert await store.query_protocols() == []
        page = await store.query_conversations()
        assert page.items == []
        assert await store.query_flow_by_id(1) is None


@pytest.mark.asyncio
class TestInfluxDBTimeRange:
    async def test_time_range_parsing_safe(self):
        from app.storage.influxdb_store import _time_range_seconds
        assert _time_range_seconds("5m") == 300
        assert _time_range_seconds("1h") == 3600
        assert _time_range_seconds("bad") == 60
