"""存储后端抽象基类 — 所有数据库实现需继承此接口。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from app.models.schemas import (
    AppStat,
    Conversation,
    DeviceProfile,
    DeviceProfileList,
    DnsClientStat,
    DnsDomainStat,
    DnsOverview,
    DnsQueryDetail,
    DnsTimePoint,
    DomainStat,
    FlowRecord,
    Page,
    ProtocolStat,
    SecurityEvent,
    SecurityOverview,
    ServiceStat,
    Talker,
    TimePoint,
    TrafficOverview,
    TrafficTotal,
)


class StorageBackend(ABC):
    """统一存储接口，所有后端必须实现以下方法。"""

    @abstractmethod
    async def initialize(self) -> None:
        """初始化数据库连接和 schema。"""
        ...

    @abstractmethod
    async def close(self) -> None:
        """关闭数据库连接。"""
        ...

    # ── 写入 ────────────────────────────────────────────

    @abstractmethod
    async def write_flow(self, flow: FlowRecord) -> int:
        """写入一条流记录，返回记录 ID。"""
        ...

    @abstractmethod
    async def write_flows_batch(self, flows: list[FlowRecord]) -> int:
        """批量写入流记录，返回写入条数。"""
        ...

    # ── 查询 ────────────────────────────────────────────

    @abstractmethod
    async def query_overview(self, time_range: str = "5m") -> TrafficOverview:
        """查询实时概览。"""
        ...

    @abstractmethod
    async def query_protocols(
        self, time_range: str = "1h", top: int = 10
    ) -> list[ProtocolStat]:
        """查询协议分布。"""
        ...

    @abstractmethod
    async def query_top_talkers(
        self, top: int = 20, time_range: str = "30m"
    ) -> list[Talker]:
        """查询流量 Top N IP。"""
        ...

    @abstractmethod
    async def query_time_series(
        self, interval: str = "10s", time_range: str = "1h"
    ) -> list[TimePoint]:
        """查询时序流量数据。"""
        ...

    @abstractmethod
    async def query_conversations(
        self,
        page: int = 1,
        size: int = 20,
        l7_proto: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        time_start: datetime | None = None,
        time_end: datetime | None = None,
    ) -> Page:
        """分页查询会话列表。"""
        ...

    @abstractmethod
    async def query_flow_by_id(self, flow_id: int) -> FlowRecord | None:
        """根据 ID 查询单条流记录。"""
        ...

    # ── 维护 ────────────────────────────────────────────

    async def cleanup_old_flows(self, retention_days: int = 7) -> int:
        """清理超过 retention_days 的旧流记录，返回删除条数。

        默认实现不做任何操作（由具体后端实现）。
        """
        return 0

    # ── 安全态势 ────────────────────────────────────────

    @abstractmethod
    async def query_security_events(
        self,
        since: datetime,
        min_score: int = 0,
        severity: str = "",
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """查询安全事件（含风险信息的流记录）。"""
        ...

    @abstractmethod
    async def query_security_overview(
        self,
        since: datetime,
        time_range: str = "1h",
    ) -> SecurityOverview:
        """查询安全态势概览统计。"""
        ...

    # ── 域名统计 ────────────────────────────────────────

    @abstractmethod
    async def query_top_domains(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[DomainStat]:
        """查询 Top N 访问域名。"""
        ...

    # ── 应用统计 ────────────────────────────────────────

    @abstractmethod
    async def query_app_stats(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[AppStat]:
        """查询应用层协议统计。"""
        ...

    # ── 流量总和 ────────────────────────────────────────

    @abstractmethod
    async def query_traffic_totals(
        self,
        since: datetime,
        time_range: str = "5m",
    ) -> TrafficTotal:
        """查询流量总和统计。"""
        ...

    # ── 应用服务统计 ────────────────────────────────────

    @abstractmethod
    async def query_services_stats(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[ServiceStat]:
        """查询应用服务流量统计。"""
        ...

    # ── DNS 统计 ────────────────────────────────────────

    async def query_dns_overview(
        self,
        since: datetime,
        time_range: str = "1h",
    ) -> DnsOverview:
        """查询 DNS 总览统计（默认空实现，SQLite 覆盖）。"""
        return DnsOverview(time_range=time_range)

    async def query_dns_top_domains(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[DnsDomainStat]:
        """查询 DNS 查询次数 Top N 域名（默认空实现，SQLite 覆盖）。"""
        return []

    async def query_dns_top_clients(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[DnsClientStat]:
        """查询 DNS 查询次数 Top N 客户端（默认空实现，SQLite 覆盖）。"""
        return []

    async def query_dns_timeseries(
        self,
        since: datetime,
        span_seconds: int,
        bucket_seconds: int,
    ) -> list[DnsTimePoint]:
        """查询 DNS 活动时序（默认空实现，SQLite 覆盖）。"""
        return []

    async def query_dns_details(
        self,
        since: datetime,
        limit: int = 100,
        domain: str = "",
        client: str = "",
    ) -> list[DnsQueryDetail]:
        """查询 DNS 查询明细（默认空实现，SQLite 覆盖）。"""
        return []

    # ── 设备画像 ────────────────────────────────────────

    @abstractmethod
    async def query_device_profiles(
        self,
        since_ts: int,
        page: int = 1,
        size: int = 20,
        sort_by: str = "bytes",
        time_range: str = "1h",
    ) -> DeviceProfileList:
        """查询设备画像列表。"""
        ...

    @abstractmethod
    async def query_device_profile_detail(
        self,
        ip: str,
        since_ts: int,
        time_range: str = "1h",
    ) -> DeviceProfile | None:
        """查询指定设备的详细画像。"""
        ...
