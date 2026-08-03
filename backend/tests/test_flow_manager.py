"""流管理器单元测试。"""

from __future__ import annotations

import time
from datetime import datetime, timezone, timedelta

import pytest

from app.flow.manager import FlowManager
from app.models.schemas import FlowRecord


class TestFlowManager:
    """FlowManager 核心功能测试。"""

    def test_empty_initial_state(self):
        """新创建的流管理器应无活跃流。"""
        fm = FlowManager()
        assert fm.active_count == 0

    def test_forward_flow_key(self):
        """验证 5-tuple 规范化 key — 正向流量。"""
        fm = FlowManager()
        key = fm._make_key("10.0.0.1", "192.168.1.1", 40000, 443, "tcp")
        # a=(10.0.0.1, 40000) < b=(192.168.1.1, 443) → client 在前
        assert key == "10.0.0.1|40000|192.168.1.1|443|tcp"

    def test_reverse_flow_key(self):
        """验证反向流量使用相同 key。"""
        fm = FlowManager()
        # 反向: server→client
        key = fm._make_key("192.168.1.1", "10.0.0.1", 443, 40000, "tcp")
        # a=(10.0.0.1, 40000) < b=(192.168.1.1, 443) → 排序后 client 在前
        assert key == "10.0.0.1|40000|192.168.1.1|443|tcp"

    def test_bidirectional_aggregation(self):
        """正反向流量应聚合到同一条流。"""
        fm = FlowManager()
        now = datetime.now(timezone.utc)

        # 正向: client → server
        forward = FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=0, packets_sent=1, packets_recv=0,
            l7_meta="", duration_ms=0,
        )
        fm.update(forward)

        # 反向: server → client
        reverse = FlowRecord(
            timestamp=now, src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=443, dst_port=40000, l4_proto="tcp", l7_proto="tls",
            bytes_sent=0, bytes_recv=200, packets_sent=0, packets_recv=1,
            l7_meta="", duration_ms=0,
        )
        fm.update(reverse)

        assert fm.active_count == 1, "正反流向应聚合为一条流"

        # 验证聚合后的统计
        flow = list(fm._flows.values())[0]
        assert flow.bytes_sent == 100
        assert flow.bytes_recv == 200
        assert flow.packets_sent == 1
        assert flow.packets_recv == 1

    def test_multiple_flows(self):
        """多条不同流应独立维护。"""
        fm = FlowManager()
        now = datetime.now(timezone.utc)

        # 流 A
        fm.update(FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2,
            l7_meta="", duration_ms=1000,
        ))
        # 流 B (不同 IP)
        fm.update(FlowRecord(
            timestamp=now, src_ip="10.0.0.2", dst_ip="192.168.1.2",
            src_port=50000, dst_port=80, l4_proto="tcp", l7_proto="http",
            bytes_sent=300, bytes_recv=400, packets_sent=3, packets_recv=4,
            l7_meta="", duration_ms=2000,
        ))

        assert fm.active_count == 2
        # 验证各自统计数据独立
        flow_a = list(fm._flows.values())[0]
        flow_b = list(fm._flows.values())[1]
        ids = {f"{f.src_ip}:{f.src_port}" for f in [flow_a, flow_b]}
        assert ids == {"10.0.0.1:40000", "10.0.0.2:50000"}


class TestFlowIdleTimeout:
    """流超时测试。"""

    def test_idle_timeout(self):
        """超时的流应被 flush_idle 清除。"""
        fm = FlowManager(idle_timeout=0)  # 立即超时
        now = datetime.now(timezone.utc)

        fm.update(FlowRecord(
            timestamp=now - timedelta(seconds=5),  # 5秒前
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2,
            l7_meta="", duration_ms=1000,
        ))

        expired = fm.flush_idle()
        assert len(expired) == 1
        assert fm.active_count == 0

    def test_long_lived_active_flow_not_flushed(self):
        """长连接持续有流量时不应被误清（回归测试）。

        流首次出现超过 idle_timeout，但最近仍有活动（last_seen 较新），
        必须保留在活跃列表，否则实时会话会断档/返回空列表。
        """
        fm = FlowManager(idle_timeout=60)
        now = datetime.now(timezone.utc)

        # 首次出现在 120 秒前（长连接）
        fm.update(FlowRecord(
            timestamp=now - timedelta(seconds=120),
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2,
            l7_meta="", duration_ms=1000,
        ))

        # 之后持续有流量（模拟 update 更新 last_seen）
        for _ in range(5):
            fm.update(FlowRecord(
                timestamp=now - timedelta(seconds=100),  # 首次时间戳保持旧值
                src_ip="10.0.0.1", dst_ip="192.168.1.1",
                src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
                bytes_sent=10, bytes_recv=20, packets_sent=1, packets_recv=1,
                l7_meta="", duration_ms=1000,
            ))

        # 模拟最后一次活动在 5 秒前
        flow = list(fm._flows.values())[0]
        flow.last_seen = now - timedelta(seconds=5)

        expired = fm.flush_idle()
        assert len(expired) == 0, "持续活跃的长连接不应被误清除"
        assert fm.active_count == 1

    def test_active_flow_not_expired(self):
        """活跃流不应被误清除。"""
        fm = FlowManager(idle_timeout=3600)  # 1 小时超时
        now = datetime.now(timezone.utc)

        fm.update(FlowRecord(
            timestamp=now,
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2,
            l7_meta="", duration_ms=1000,
        ))

        expired = fm.flush_idle()
        assert len(expired) == 0
        assert fm.active_count == 1

    def test_partial_timeout(self):
        """部分超时时应只清除超时流。"""
        fm = FlowManager(idle_timeout=10)
        now = datetime.now(timezone.utc)

        # 过期流
        fm.update(FlowRecord(
            timestamp=now - timedelta(seconds=60),
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=200, packets_sent=1, packets_recv=2,
            l7_meta="", duration_ms=1000,
        ))
        # 活跃流
        fm.update(FlowRecord(
            timestamp=now,
            src_ip="10.0.0.2", dst_ip="192.168.1.2",
            src_port=50000, dst_port=80, l4_proto="tcp", l7_proto="http",
            bytes_sent=300, bytes_recv=400, packets_sent=3, packets_recv=4,
            l7_meta="", duration_ms=2000,
        ))

        expired = fm.flush_idle()
        assert len(expired) == 1
        assert expired[0].src_ip == "10.0.0.1"
        assert fm.active_count == 1
        remaining = list(fm._flows.values())[0]
        assert remaining.src_ip == "10.0.0.2"


class TestFlowMetadata:
    """流元数据更新测试。"""

    def test_l7_meta_update(self):
        """后续包的 l7_meta 应覆盖更新。"""
        fm = FlowManager()
        now = datetime.now(timezone.utc)

        # 第一条: 无 meta
        fm.update(FlowRecord(
            timestamp=now, src_ip="10.0.0.1", dst_ip="192.168.1.1",
            src_port=40000, dst_port=443, l4_proto="tcp", l7_proto="tls",
            bytes_sent=100, bytes_recv=0, packets_sent=1, packets_recv=0,
            l7_meta="", duration_ms=0,
        ))
        # 第二条: 有 meta
        fm.update(FlowRecord(
            timestamp=now, src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=443, dst_port=40000, l4_proto="tcp", l7_proto="tls",
            bytes_sent=0, bytes_recv=200, packets_sent=0, packets_recv=1,
            l7_meta="sni.example.com", duration_ms=0,
        ))

        flow = list(fm._flows.values())[0]
        assert flow.l7_meta == "sni.example.com"
