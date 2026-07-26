"""ClickHouse 存储后端实现（可选 — 需要安装 clickhouse-driver）。

TODO: 此后端尚未完全实现。当前所有查询返回空数据。
完整实现需要:
  1. pip install clickhouse-driver
  2. 实现 write_flow/write_flows_batch
  3. 实现 MergeTree 查询
  4. `scripts/clickhouse_init.sql` 已可用
"""

from __future__ import annotations

import logging
from datetime import datetime

from app.config import ClickHouseConfig
from app.models.schemas import (
    FlowRecord,
    Page,
    ProtocolStat,
    Talker,
    TimePoint,
    TrafficOverview,
)
from app.storage.base import StorageBackend

logger = logging.getLogger(__name__)


class ClickHouseStore(StorageBackend):
    """ClickHouse 存储后端（待实现）。"""

    def __init__(self, config: ClickHouseConfig) -> None:
        self.config = config
        self._client = None

    async def initialize(self) -> None:
        logger.warning("ClickHouse 后端尚未完整实现，所有查询将返回空数据")

    async def close(self) -> None:
        pass

    async def write_flow(self, flow: FlowRecord) -> int:
        return 0

    async def write_flows_batch(self, flows: list[FlowRecord]) -> int:
        return 0

    async def query_overview(self, time_range: str = "5m") -> TrafficOverview:
        return TrafficOverview(time_range=time_range)

    async def query_protocols(
        self, time_range: str = "1h", top: int = 10
    ) -> list[ProtocolStat]:
        return []

    async def query_top_talkers(
        self, top: int = 20, time_range: str = "30m"
    ) -> list[Talker]:
        return []

    async def query_time_series(
        self, interval: str = "10s", time_range: str = "1h"
    ) -> list[TimePoint]:
        return []

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
        return Page(items=[], total=0, page=page, size=size, pages=0)

    async def query_flow_by_id(self, flow_id: int) -> FlowRecord | None:
        return None
