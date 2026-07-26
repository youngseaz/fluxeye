"""SQLite 存储后端单元测试。"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone, timedelta

import pytest

from app.config import SQLiteConfig
from app.models.schemas import FlowRecord
from app.storage.sqlite_store import SQLiteStore


@pytest.mark.asyncio
class TestSQLiteStoreLifecycle:
    """SQLiteStore 生命周期测试。"""

    async def test_initialize_creates_file(self):
        """初始化应创建数据库文件。"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.unlink(path)  # 删除空文件
        store = SQLiteStore(SQLiteConfig(path=path))
        await store.initialize()
        assert os.path.exists(path)
        await store.close()
        os.unlink(path)

    async def test_initialize_creates_tables(self):
        """初始化应创建 flows 表。"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        store = SQLiteStore(SQLiteConfig(path=path))
        await store.initialize()

        # 验证表存在
        import aiosqlite
        conn = await aiosqlite.connect(path)
        cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in await cursor.fetchall()]
        await conn.close()
        assert "flows" in tables

        await store.close()
        os.unlink(path)

    async def test_close_releases_connection(self):
        """关闭后应释放连接。"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        store = SQLiteStore(SQLiteConfig(path=path))
        await store.initialize()
        await store.close()
        # 不应报错
        assert True


@pytest.mark.asyncio
class TestSQLiteStoreWrite:
    """写入操作测试。"""

    async def test_write_flow(self, sqlite_store: SQLiteStore):
        """写入单条流记录应返回正数 ID。"""
        now = datetime.now(timezone.utc)
        flow = FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp",
            l7_proto="tls", bytes_sent=100, bytes_recv=200,
            packets_sent=5, packets_recv=10, l7_meta="test.com",
            duration_ms=5000,
        )
        flow_id = await sqlite_store.write_flow(flow)
        assert flow_id > 0

    async def test_write_flow_zero_bytes(self):
        """零字节的流也应能写入。"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        store = SQLiteStore(SQLiteConfig(path=path))
        await store.initialize()

        now = datetime.now(timezone.utc)
        flow = FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp",
            l7_proto="unknown", bytes_sent=0, bytes_recv=0,
            packets_sent=0, packets_recv=0, l7_meta="", duration_ms=0,
        )
        flow_id = await store.write_flow(flow)
        assert flow_id > 0
        await store.close()
        os.unlink(path)

    async def test_write_flows_batch(self, sqlite_store: SQLiteStore):
        """批量写入应返回写入条数。"""
        now = datetime.now(timezone.utc)
        flows = [
            FlowRecord(
                timestamp=now, src_ip=f"10.0.0.{i}", dst_ip="192.168.1.1",
                src_port=40000 + i, dst_port=443, l4_proto="tcp",
                l7_proto="tls", bytes_sent=100, bytes_recv=200,
                packets_sent=5, packets_recv=10, l7_meta="", duration_ms=1000,
            )
            for i in range(10)
        ]
        count = await sqlite_store.write_flows_batch(flows)
        assert count == 10


@pytest.mark.asyncio
class TestSQLiteStoreQuery:
    """查询操作测试。"""

    async def test_query_overview_empty(self, sqlite_store: SQLiteStore):
        """空数据库应返回零值概览。"""
        overview = await sqlite_store.query_overview(time_range="1h")
        assert overview.total_bps == 0.0
        assert overview.total_pps == 0.0
        assert overview.active_flows == 0
        assert overview.total_connections == 0

    async def test_query_overview_with_data(self, sqlite_store_with_data: SQLiteStore):
        """有数据时概览应返回正确统计。"""
        overview = await sqlite_store_with_data.query_overview(time_range="1h")
        assert overview.total_connections > 0
        assert overview.total_bps >= 0

    async def test_query_conversations(self, sqlite_store_with_data: SQLiteStore):
        """分页查询会话列表。"""
        page = await sqlite_store_with_data.query_conversations(page=1, size=5)
        assert len(page.items) == 5
        assert page.total == 20
        assert page.page == 1
        assert page.size == 5
        assert page.pages == 4

    async def test_query_conversations_with_filter(self, sqlite_store_with_data: SQLiteStore):
        """按协议过滤会话。"""
        page = await sqlite_store_with_data.query_conversations(
            page=1, size=20, l7_proto="tls"
        )
        assert len(page.items) > 0
        for item in page.items:
            assert item.l7_proto == "tls"

    async def test_query_conversations_has_all_fields(self, sqlite_store_with_data: SQLiteStore):
        """会话记录应包含所有必要字段。"""
        page = await sqlite_store_with_data.query_conversations(page=1, size=1)
        item = page.items[0]
        assert item.packets_sent >= 0
        assert item.packets_recv >= 0
        assert isinstance(item.l7_meta, str)

    async def test_query_flow_by_id(self, sqlite_store_with_data: SQLiteStore):
        """按 ID 查询流详情。"""
        # 先获取第一条 ID
        page = await sqlite_store_with_data.query_conversations(page=1, size=1)
        first_id = page.items[0].id

        flow = await sqlite_store_with_data.query_flow_by_id(first_id)
        assert flow is not None
        assert flow.src_ip is not None
        assert flow.dst_ip is not None
        assert flow.packets_sent >= 0
        assert flow.packets_recv >= 0
        assert isinstance(flow.l7_meta, str)

    async def test_query_flow_by_id_not_found(self, sqlite_store: SQLiteStore):
        """不存在的 ID 应返回 None。"""
        flow = await sqlite_store.query_flow_by_id(99999)
        assert flow is None

    async def test_query_protocols(self, sqlite_store_with_data: SQLiteStore):
        """查询协议分布。"""
        protocols = await sqlite_store_with_data.query_protocols(time_range="1h")
        assert len(protocols) > 0
        total_pct = sum(p.percentage for p in protocols)
        assert abs(total_pct - 100.0) < 0.01  # 总和应接近 100%

    async def test_query_top_talkers(self, sqlite_store_with_data: SQLiteStore):
        """查询 Top Talkers。"""
        talkers = await sqlite_store_with_data.query_top_talkers(top=5, time_range="1h")
        assert len(talkers) <= 5
        if talkers:
            # 按流量降序排列
            for i in range(len(talkers) - 1):
                assert talkers[i].bytes_total >= talkers[i + 1].bytes_total

    async def test_query_time_series(self, sqlite_store_with_data: SQLiteStore):
        """查询时序数据。"""
        series = await sqlite_store_with_data.query_time_series(
            interval="10s", time_range="1h"
        )
        assert len(series) > 0
        for point in series:
            assert point.bps >= 0
            assert point.pps >= 0
