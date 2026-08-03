"""流管理器 — 5-tuple 会话聚合与状态管理。"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.schemas import FlowRecord


class FlowManager:
    """流管理器，维护活跃会话状态，5-tuple 聚合。"""

    def __init__(self, idle_timeout: int = 60):
        self.idle_timeout = idle_timeout
        self._flows: dict[str, FlowRecord] = {}
        self._first_seen: dict[str, datetime] = {}

    def _make_key(self, src_ip: str, dst_ip: str, src_port: int,
                  dst_port: int, l4_proto: str) -> str:
        """生成规范化 5-tuple 流标识，双向使用同一 key。"""
        # 将 (src_ip, src_port) 和 (dst_ip, dst_port) 按序排列
        # 确保 client→server 和 server→client 映射到同一流
        # 使用 | 分隔避免与 IPv6 地址中的 : 冲突
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a < b:
            return f"{src_ip}|{src_port}|{dst_ip}|{dst_port}|{l4_proto}"
        else:
            return f"{dst_ip}|{dst_port}|{src_ip}|{src_port}|{l4_proto}"

    def update(self, flow: FlowRecord) -> FlowRecord | None:
        """更新流状态。返回已关闭的流（如超时），或 None。"""
        key = self._make_key(
            flow.src_ip, flow.dst_ip,
            flow.src_port, flow.dst_port,
            flow.l4_proto,
        )

        now = datetime.now(timezone.utc)
        existing = self._flows.get(key)
        if existing:
            existing.bytes_sent += flow.bytes_sent
            existing.bytes_recv += flow.bytes_recv
            existing.packets_sent += flow.packets_sent
            existing.packets_recv += flow.packets_recv
            existing.last_seen = now
            # 时长 = last_seen - first_seen
            first = self._first_seen.get(key, existing.timestamp)
            delta_ms = int((now - first).total_seconds() * 1000)
            existing.duration_ms = max(0, delta_ms)  # 确保非负
            if flow.l7_meta:
                existing.l7_meta = flow.l7_meta
            if flow.dst_host:
                existing.dst_host = flow.dst_host
            return None
        else:
            flow.first_seen = flow.timestamp
            flow.last_seen = flow.timestamp
            self._first_seen[key] = flow.timestamp
            self._flows[key] = flow
            return None

    def flush_idle(self) -> list[FlowRecord]:
        """清除超时流，返回已关闭的流列表。

        基于「最后活动时间 last_seen」判断是否空闲，而不是流的首次时间戳
        timestamp——否则长连接(> idle_timeout 秒)即使持续有流量也会被误清，
        导致实时会话出现断档/空列表。
        """
        now = datetime.now(timezone.utc)
        expired = []
        keys_to_delete = []
        for key, flow in self._flows.items():
            last_activity = flow.last_seen or flow.timestamp
            if (now - last_activity).total_seconds() > self.idle_timeout:
                # 刷出时重新计算时长，确保准确
                first = self._first_seen.get(key, flow.timestamp)
                delta_ms = int((now - first).total_seconds() * 1000)
                flow.duration_ms = max(0, delta_ms)
                flow.last_seen = now
                expired.append(flow)
                keys_to_delete.append(key)
        for key in keys_to_delete:
            del self._flows[key]
            self._first_seen.pop(key, None)
        self._last_flushed_keys = keys_to_delete
        if len(expired) >= 50:
            from app.utils.logger import get_logger
            get_logger("flow.manager").warning(
                "[DIAG] 单次刷出大量空闲流: %d 条 (剩余活跃 %d), idle_timeout=%ds — 可能是流量骤停或误清",
                len(expired), len(self._flows), self.idle_timeout,
            )
        return expired

    def get_last_flushed_keys(self) -> list[str]:
        """返回上一次 flush_idle 清除的 flow keys。"""
        return getattr(self, '_last_flushed_keys', [])

    def get_active_flows(self) -> list[FlowRecord]:
        """返回当前所有活跃流（按最近活动倒序）。"""
        flows = list(self._flows.values())
        flows.sort(key=lambda f: f.last_seen or f.timestamp, reverse=True)
        return flows

    @property
    def active_count(self) -> int:
        return len(self._flows)
