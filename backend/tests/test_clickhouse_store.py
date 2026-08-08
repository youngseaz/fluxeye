"""ClickHouseStore 单元测试 — 使用 fake 客户端验证 SQL 生成、结果映射、注入安全。"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.config import ClickHouseConfig
from app.models.schemas import FlowRecord
from app.storage.clickhouse_store import ClickHouseStore


class FakeClient:
    """记录 execute 调用并按 SQL 特征返回预设结果的 fake Client（同步）。"""

    def __init__(self, results: dict[str, list] | None = None):
        self.calls: list[tuple[str, dict | None]] = []
        self.inserts: list[list] = []
        self.results = results or {}

    def execute(self, sql: str, params: dict | None = None):
        self.calls.append((sql, params))
        if sql.strip().upper().startswith("INSERT"):
            self.inserts.extend(params or [])
            return len(params or [])
        for key, val in self.results.items():
            if key in sql:
                return val
        return []

    def disconnect(self):
        pass


def _store(results: dict[str, list] | None = None) -> ClickHouseStore:
    store = ClickHouseStore(ClickHouseConfig())
    store._client = FakeClient(results)
    store._available = True
    return store


def _flow(**over) -> FlowRecord:
    base = dict(
        timestamp=datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.0.1", dst_ip="93.184.216.34",
        src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
        bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2,
        l7_meta="", duration_ms=1000, dst_host="www.example.com",
        risks=[{"id": 1, "name": "x", "severity": 1}], risk_score=50,
    )
    base.update(over)
    return FlowRecord(**base)


@pytest.mark.asyncio
class TestClickHouseWrite:
    async def test_write_flow_returns_id_and_inserts(self):
        store = _store()
        fid = await store.write_flow(_flow())
        assert fid == 1
        assert len(store._client.inserts) == 1
        row = store._client.inserts[0]
        assert row[0] == 1          # flow_id
        assert row[4] == "10.0.0.1"  # src_ip
        assert row[5] == "93.184.216.34"
        assert row[8] == "tcp"
        assert row[9] == "tls"
        assert row[30] == 50        # risk_score

    async def test_write_flows_batch(self):
        store = _store()
        n = await store.write_flows_batch([_flow(), _flow(src_ip="10.0.0.2")])
        assert n == 2
        assert len(store._client.inserts) == 2
        assert store._client.inserts[0][0] == 1
        assert store._client.inserts[1][0] == 2

    async def test_write_unavailable_returns_zero(self):
        store = ClickHouseStore(ClickHouseConfig())
        store._available = False
        assert await store.write_flow(_flow()) == 0
        assert await store.write_flows_batch([_flow()]) == 0


@pytest.mark.asyncio
class TestClickHouseQuery:
    async def test_query_overview(self):
        store = _store({"sum(bytes_sent + bytes_recv)": [[1000, 100, 5]]})
        ov = await store.query_overview(time_range="1m")
        assert ov.total_connections == 5
        assert ov.active_flows == 5
        assert ov.total_bps > 0

    async def test_query_protocols(self):
        store = _store({"GROUP BY l7_proto": [["http", 500, 3], ["tls", 300, 2]]})
        protos = await store.query_protocols(top=10)
        assert len(protos) == 2
        assert protos[0].l7_proto == "http"
        assert protos[0].bytes_total == 500
        assert protos[0].flow_count == 3

    async def test_query_conversations_maps_and_filters(self):
        row = [
            1, datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
            "10.0.0.1", "93.184.216.34", 40000, 443, "tcp", "tls",
            100, 200, 1, 2, "", "", 1000, "", "www.example.com",
            "US", "", "", 0, "", 0.0, 0.0, "",
        ]
        store = _store({"SELECT count()": [[1]], "SELECT flow_id, timestamp": [row]})
        page = await store.query_conversations(l7_proto="tls", src_ip="10.0.0.1")
        assert page.total == 1
        assert page.pages == 1
        assert len(page.items) == 1
        c = page.items[0]
        assert c.l7_proto == "tls"
        assert c.dst_host == "www.example.com"
        # 验证过滤条件进入 SQL 且值走参数绑定（防注入）
        sql, params = store._client.calls[0]
        assert "l7_proto = %(l7)s" in sql
        assert params["l7"] == "tls"
        assert "10.0.0.1" not in sql  # 值未拼进 SQL

    async def test_query_conversations_injection_safe(self):
        store = _store({"SELECT count()": [[0]]})
        payload = "'; DROP TABLE flows; --"
        page = await store.query_conversations(l7_proto=payload, src_ip=payload)
        assert page.total == 0
        sql, params = store._client.calls[0]
        assert payload not in sql  # 注入载荷未进入 SQL 文本
        assert params["l7"] == payload  # 仅作为参数值

    async def test_query_flow_by_id(self):
        row = [
            7, datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc),
            "aa:bb", "cc:dd", "10.0.0.1", "93.184.216.34",
            40000, 443, "tcp", "tls", 100, 200, 1, 2, "", "", 1000, "",
            None, None, "www.example.com", "US", "", "", 0, "", 0.0, 0.0,
            "/tmp/x.pcap", '[{"id":1,"name":"x","severity":2,"severity_name":"medium","info":""}]', 80,
        ]
        store = _store({"flow_id = %(fid)s": [row]})
        flow = await store.query_flow_by_id(7)
        assert flow is not None
        assert flow.src_ip == "10.0.0.1"
        assert flow.risk_score == 80
        assert flow.risks[0]["name"] == "x"
        assert flow.pcap_file == "/tmp/x.pcap"

    async def test_query_flow_by_id_not_found(self):
        store = _store({"flow_id = %(fid)s": []})
        assert await store.query_flow_by_id(999) is None

    async def test_query_unavailable_returns_empty(self):
        store = ClickHouseStore(ClickHouseConfig())
        store._available = False
        assert (await store.query_overview()).total_connections == 0
        assert await store.query_protocols() == []
        page = await store.query_conversations()
        assert page.items == [] and page.total == 0
        assert await store.query_flow_by_id(1) is None


@pytest.mark.asyncio
class TestClickHouseTimeRange:
    async def test_time_range_parsing_safe(self):
        from app.storage.clickhouse_store import _time_range_seconds
        assert _time_range_seconds("5m") == 300
        assert _time_range_seconds("1h") == 3600
        assert _time_range_seconds("1h; DROP TABLE flows; --") == 60  # 非法回退默认
        assert _time_range_seconds("abc") == 60
