"""SQL 注入安全回归测试。

项目所有 SQL 均集中在 app.storage.sqlite_store 中且使用参数化查询（? 占位符）。
本套测试通过真实注入载荷验证：
  1. 用户可控参数（l7_proto / src_ip / dst_ip / domain / client / sort_by /
     time_range / flow_id）无法改变 SQL 语义或破坏表结构
  2. 注入尝试后 flows 表仍存在、数据仍完整
  3. 非法 time_range 不再导致 500 崩溃（防 DoS）

若这些测试失败，说明出现了 SQL 拼接回归，需立即修复。
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

# 常见注入载荷
DROP_TABLE = "' OR 1=1; DROP TABLE flows; --"
UNION_SELECT = "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28; --"
TIME_BLIND = "1h; SELECT sleep(5); --"
SORT_INJECT = "total_bytes DESC; DROP TABLE flows;--"
LIKE_WILDCARD = "%' OR '1'='1 --"


@pytest.mark.asyncio
class TestSQLInjection:
    """针对各查询入口的注入回归测试。"""

    async def test_conversations_l7_proto_injection(self, sqlite_store_with_data):
        page = await sqlite_store_with_data.query_conversations(
            page=1, size=20, l7_proto=DROP_TABLE
        )
        # 注入载荷应被当作字面值匹配，无结果且不报错
        assert page.total == 0
        assert page.items == []

    async def test_conversations_src_ip_injection(self, sqlite_store_with_data):
        page = await sqlite_store_with_data.query_conversations(
            page=1, size=20, src_ip=UNION_SELECT
        )
        assert page.total == 0
        assert page.items == []

    async def test_conversations_dst_ip_injection(self, sqlite_store_with_data):
        page = await sqlite_store_with_data.query_conversations(
            page=1, size=20, dst_ip="' OR '1'='1"
        )
        assert page.total == 0
        assert page.items == []

    async def test_conversations_combined_injection(self, sqlite_store_with_data):
        """组合注入：多个过滤条件同时带载荷。"""
        page = await sqlite_store_with_data.query_conversations(
            page=1, size=20,
            l7_proto=DROP_TABLE,
            src_ip=UNION_SELECT,
            dst_ip="'; DROP TABLE flows;--",
        )
        assert page.total == 0
        assert page.items == []

    async def test_device_profiles_sort_by_injection(self, sqlite_store_with_data):
        """sort_by 注入：应回退到白名单默认排序，不改变 SQL 语义。"""
        since = int(datetime.now(timezone.utc).timestamp()) - 86400
        result = await sqlite_store_with_data.query_device_profiles(
            since_ts=since, page=1, size=20, sort_by=SORT_INJECT
        )
        # 不崩溃，且返回正常（20 条数据应有 5 个不同 src_ip）
        assert result.total > 0
        assert len(result.devices) > 0

    async def test_overview_time_range_injection(self, sqlite_store_with_data):
        """time_range 注入：应安全回退为默认 60s，不崩溃（防 DoS）。"""
        overview = await sqlite_store_with_data.query_overview(time_range=TIME_BLIND)
        # 返回有效统计对象（不会抛 ValueError）
        assert overview is not None
        assert overview.time_range == TIME_BLIND  # 原样回显，但内部按 60s 计算
        assert overview.total_bps >= 0

    async def test_time_range_invalid_returns_default(self, sqlite_store_with_data):
        span = await sqlite_store_with_data._get_time_range_seconds(TIME_BLIND)
        assert span == 60  # 非法输入回退默认
        assert await sqlite_store_with_data._get_time_range_seconds("abc") == 60
        assert await sqlite_store_with_data._get_time_range_seconds("") == 60
        assert await sqlite_store_with_data._get_time_range_seconds("5m") == 300

    async def test_dns_details_domain_injection(self, sqlite_store_with_data):
        since = datetime.now(timezone.utc)
        rows = await sqlite_store_with_data.query_dns_details(
            since=since, limit=100, domain=LIKE_WILDCARD
        )
        assert isinstance(rows, list)

    async def test_dns_details_client_injection(self, sqlite_store_with_data):
        since = datetime.now(timezone.utc)
        rows = await sqlite_store_with_data.query_dns_details(
            since=since, limit=100, client=DROP_TABLE
        )
        assert isinstance(rows, list)

    async def test_flow_id_negative_and_injection(self, sqlite_store_with_data):
        # flow_id 为整数参数，非法值返回 None 而非报错
        assert await sqlite_store_with_data.query_flow_by_id(-999) is None
        assert await sqlite_store_with_data.query_flow_by_id(0) is None

    async def test_table_survives_all_injection_vectors(self, sqlite_store_with_data):
        """综合验证：所有注入向量后 flows 表仍存在且数据完整。"""
        # 先记录基线
        page = await sqlite_store_with_data.query_conversations(page=1, size=100)
        baseline = page.total
        assert baseline > 0

        # 执行一轮注入尝试
        await sqlite_store_with_data.query_conversations(l7_proto=DROP_TABLE)
        await sqlite_store_with_data.query_conversations(src_ip=UNION_SELECT)
        await sqlite_store_with_data.query_conversations(dst_ip="'; DROP TABLE flows;--")
        await sqlite_store_with_data.query_overview(time_range=TIME_BLIND)
        since = int(datetime.now(timezone.utc).timestamp()) - 86400
        await sqlite_store_with_data.query_device_profiles(since_ts=since, sort_by=SORT_INJECT)

        # 再次查询：表应存在、数据完整
        page2 = await sqlite_store_with_data.query_conversations(page=1, size=100)
        assert page2.total == baseline, "注入后数据被破坏！"
