"""InfluxDB 2.x 存储后端实现（基于 influxdb-client）。

将每条流记录写为 influxdb measurement "flows" 的一个 Point：
  - tags（低基数，用于分组过滤）: src_ip/dst_ip/port/l4/l7/category/mac/interface/country
  - fields: bytes/packets/duration/risk/geo/dst_host/pcap/l7_meta/risks/flow_id
查询使用 Flux 语句。由于 InfluxDB 为时序数据库、每条流一个 Point，
流记录查询（conversations / flow detail）按时间范围 + tag 过滤实现。
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
from datetime import datetime, timezone

from app.config import InfluxDBConfig
from app.models.schemas import (
    AppStat,
    Conversation,
    DeviceProfile,
    DeviceProfileList,
    DomainStat,
    FlowRecord,
    Page,
    ProtocolStat,
    RiskDetail,
    SecurityEvent,
    SecurityOverview,
    ServiceStat,
    Talker,
    TimePoint,
    TrafficOverview,
    TrafficTotal,
)
from app.storage.base import StorageBackend
from app.storage.sqlite_store import SQLiteStore  # 复用服务名映射

logger = logging.getLogger(__name__)

MEASUREMENT = "flows"


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _time_range_seconds(time_range: str) -> int:
    try:
        unit = time_range[-1]
        value = int(time_range[:-1])
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        return value * multipliers.get(unit, 60)
    except (ValueError, TypeError, IndexError):
        return 60


def _dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return None


def _flux_str(value: str) -> str:
    """转义 Flux 字符串字面量（防注入）。"""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


class InfluxDBStore(StorageBackend):
    """InfluxDB 2.x 存储后端。"""

    def __init__(self, config: InfluxDBConfig) -> None:
        self.config = config
        self._client = None
        self._available = False
        self._id_counter = itertools.count(1)

    # ── 连接/初始化 ──────────────────────────────────────

    async def initialize(self) -> None:
        try:
            from influxdb_client import InfluxDBClient
            self._client = InfluxDBClient(
                url=self.config.url,
                token=self.config.token,
                org=self.config.org,
            )
            # ping 验证连接/权限，避免误报可用
            ok = await asyncio.to_thread(self._client.ping)
            self._available = bool(ok)
            if self._available:
                logger.info("InfluxDB 存储已连接: %s org=%s bucket=%s",
                            self.config.url, self.config.org, self.config.bucket)
            else:
                logger.warning("InfluxDB ping 失败，存储不可用")
        except Exception as e:
            self._available = False
            logger.warning("InfluxDB 连接失败，存储不可用: %s", e)

    async def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        self._available = False

    # ── 写入 ────────────────────────────────────────────

    def _to_point(self, flow: FlowRecord, flow_id: int):
        from influxdb_client import Point
        ts = flow.timestamp
        if not isinstance(ts, datetime):
            ts = datetime.fromtimestamp(ts.timestamp(), tz=timezone.utc)
        return (
            Point(MEASUREMENT)
            .tag("src_ip", flow.src_ip)
            .tag("dst_ip", flow.dst_ip)
            .tag("src_port", str(flow.src_port))
            .tag("dst_port", str(flow.dst_port))
            .tag("l4_proto", flow.l4_proto)
            .tag("l7_proto", flow.l7_proto)
            .tag("l7_category", flow.l7_category)
            .tag("src_mac", flow.src_mac)
            .tag("dst_mac", flow.dst_mac)
            .tag("interface", flow.interface)
            .tag("dst_country", flow.dst_country)
            .field("flow_id", flow_id)
            .field("bytes_sent", flow.bytes_sent)
            .field("bytes_recv", flow.bytes_recv)
            .field("packets_sent", flow.packets_sent)
            .field("packets_recv", flow.packets_recv)
            .field("duration_ms", flow.duration_ms)
            .field("dst_asn", flow.dst_asn)
            .field("dst_lat", flow.dst_lat)
            .field("dst_lon", flow.dst_lon)
            .field("risk_score", flow.risk_score)
            .field("dst_host", flow.dst_host)
            .field("dst_as_org", flow.dst_as_org)
            .field("dst_region", flow.dst_region)
            .field("dst_city", flow.dst_city)
            .field("pcap_file", flow.pcap_file)
            .field("l7_meta", flow.l7_meta)
            .field("risks", json.dumps(flow.risks, ensure_ascii=False))
            .time(ts)
        )

    async def write_flow(self, flow: FlowRecord) -> int:
        if not self._available or self._client is None:
            return 0
        flow_id = next(self._id_counter)
        await self._write_points([self._to_point(flow, flow_id)])
        return flow_id

    async def write_flows_batch(self, flows: list[FlowRecord]) -> int:
        if not self._available or self._client is None or not flows:
            return 0
        points = [self._to_point(f, next(self._id_counter)) for f in flows]
        await self._write_points(points)
        return len(points)

    async def _write_points(self, points) -> None:
        def _do():
            from influxdb_client.client.write_api import SYNCHRONOUS
            self._client.write_api(write_options=SYNCHRONOUS).write(
                bucket=self.config.bucket, org=self.config.org, record=points
            )
        try:
            await asyncio.to_thread(_do)
        except Exception as e:
            logger.error("InfluxDB 写入失败: %s", e)

    # ── 查询辅助 ────────────────────────────────────────

    async def _q(self, flux: str) -> list:
        """执行 Flux 查询，返回 FluxTable 列表；不可用时返回 []。"""
        if not self._available or self._client is None:
            return []
        try:
            def _do():
                return self._client.query_api().query(query=flux)
            return await asyncio.to_thread(_do)
        except Exception as e:
            logger.error("InfluxDB 查询失败: %s | Flux: %.200s", e, flux)
            return []

    def _bucket(self) -> str:
        return self.config.bucket

    @staticmethod
    def _scalar(tables, default=0):
        """从 Flux 结果中取单一数值。"""
        for t in tables:
            for rec in t.records:
                try:
                    return float(rec.get_value())
                except (TypeError, ValueError):
                    continue
        return default

    @staticmethod
    def _rows(tables) -> list:
        """将 FluxTable 展平为 dict 行列表。"""
        rows = []
        for t in tables:
            for rec in t.records:
                rows.append(dict(rec.values))
        return rows

    # ── 概览 ────────────────────────────────────────────

    async def query_overview(self, time_range: str = "5m") -> TrafficOverview:
        span = max(1, _time_range_seconds(time_range))
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "bytes_sent" or r._field == "bytes_recv")
  |> group()
  |> sum(column:"_value")
'''
        total_bytes = self._scalar(await self._q(flux))
        flux_pkt = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "packets_sent" or r._field == "packets_recv")
  |> group()
  |> sum(column:"_value")
'''
        total_packets = self._scalar(await self._q(flux_pkt))
        flux_cnt = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "flow_id")
  |> distinct(column:"_value")
  |> count()
'''
        flow_count = int(self._scalar(await self._q(flux_cnt)))
        return TrafficOverview(
            total_bps=total_bytes / span * 8,
            total_pps=total_packets / span,
            active_flows=flow_count,
            total_connections=flow_count,
            time_range=time_range,
        )

    async def query_protocols(
        self, time_range: str = "1h", top: int = 10
    ) -> list[ProtocolStat]:
        span = max(1, _time_range_seconds(time_range))
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "bytes_sent" or r._field == "bytes_recv")
  |> group(columns:["l7_proto"])
  |> sum(column:"_value")
  |> keep(columns:["l7_proto", "_value"])
  |> sort(columns:["_value"], desc:true)
  |> limit(n:{top})
'''
        rows = self._rows(await self._q(flux))
        total = sum(r.get("_value", 0) for r in rows) or 1
        return [ProtocolStat(l7_proto=r.get("l7_proto", "unknown"),
                             bytes_total=int(r.get("_value", 0)),
                             flow_count=0,
                             percentage=round(r.get("_value", 0) / total * 100, 2))
                for r in rows]

    async def query_top_talkers(
        self, top: int = 20, time_range: str = "30m"
    ) -> list[Talker]:
        span = max(1, _time_range_seconds(time_range))
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "bytes_sent")
  |> group(columns:["src_ip"])
  |> sum(column:"_value")
  |> keep(columns:["src_ip", "_value"])
  |> sort(columns:["_value"], desc:true)
  |> limit(n:{top})
'''
        rows = self._rows(await self._q(flux))
        talkers = [Talker(ip=r.get("src_ip", ""), bytes_total=int(r.get("_value", 0)),
                          direction="egress") for r in rows]
        return talkers

    async def query_time_series(
        self, interval: str = "10s", time_range: str = "1h"
    ) -> list[TimePoint]:
        span = max(1, _time_range_seconds(time_range))
        interval_s = max(1, _time_range_seconds(interval))
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "bytes_sent" or r._field == "bytes_recv")
  |> aggregateWindow(every: {interval_s}s, fn: sum, createEmpty:false)
  |> group()
'''
        rows = self._rows(await self._q(flux))
        return [TimePoint(
            timestamp=_dt(r.get("_time")) or datetime.now(timezone.utc),
            bps=(r.get("_value", 0) or 0) / interval_s * 8,
            pps=0,
        ) for r in rows]

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
        span = _time_range_seconds("6h")
        b = self._bucket()
        conds = [f'r._measurement == "{MEASUREMENT}"', 'r._field == "flow_id"']
        if l7_proto:
            conds.append(f'r.l7_proto == "{_flux_str(l7_proto)}"')
        if src_ip:
            conds.append(f'r.src_ip == "{_flux_str(src_ip)}"')
        if dst_ip:
            conds.append(f'r.dst_ip == "{_flux_str(dst_ip)}"')
        filter_expr = " and ".join(conds)
        start_expr = f"{span}s"
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{start_expr})
  |> filter(fn:(r)=> {filter_expr})
  |> pivot(rowKey:["_time"], columnKey:["_field"], valueColumn:"_value")
  |> sort(columns:["_time"], desc:true)
  |> limit(n:{page * size})
'''
        tables = await self._q(flux)
        rows = self._rows(tables)
        items = []
        for r in rows[ (page - 1) * size: page * size ]:
            items.append(self._row_to_conversation(r))
        return Page(items=items, total=len(rows), page=page, size=size,
                    pages=(len(rows) + size - 1) // size if size else 0)

    @staticmethod
    def _row_to_conversation(r: dict) -> Conversation:
        return Conversation(
            id=int(r.get("flow_id", 0) or 0),
            timestamp=_dt(r.get("_time")) or datetime.now(timezone.utc),
            src_ip=r.get("src_ip", ""), dst_ip=r.get("dst_ip", ""),
            src_port=int(r.get("src_port", 0) or 0),
            dst_port=int(r.get("dst_port", 0) or 0),
            l4_proto=r.get("l4_proto", ""), l7_proto=r.get("l7_proto", ""),
            bytes_sent=int(r.get("bytes_sent", 0) or 0),
            bytes_recv=int(r.get("bytes_recv", 0) or 0),
            packets_sent=int(r.get("packets_sent", 0) or 0),
            packets_recv=int(r.get("packets_recv", 0) or 0),
            l7_meta=r.get("l7_meta", ""), l7_category=r.get("l7_category", ""),
            duration_ms=int(r.get("duration_ms", 0) or 0),
            interface=r.get("interface", ""), dst_host=r.get("dst_host", ""),
            dst_country=r.get("dst_country", ""),
            dst_asn=int(r.get("dst_asn", 0) or 0),
        )

    async def query_flow_by_id(self, flow_id: int) -> FlowRecord | None:
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -365d)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "flow_id" and r._value == {flow_id})
  |> pivot(rowKey:["_time"], columnKey:["_field"], valueColumn:"_value")
'''
        rows = self._rows(await self._q(flux))
        if not rows:
            return None
        r = rows[0]
        try:
            risks = json.loads(r.get("risks", "[]") or "[]")
        except (json.JSONDecodeError, TypeError):
            risks = []
        return FlowRecord(
            timestamp=_dt(r.get("_time")) or datetime.now(timezone.utc),
            src_mac=r.get("src_mac", ""), dst_mac=r.get("dst_mac", ""),
            src_ip=r.get("src_ip", ""), dst_ip=r.get("dst_ip", ""),
            src_port=int(r.get("src_port", 0) or 0),
            dst_port=int(r.get("dst_port", 0) or 0),
            l4_proto=r.get("l4_proto", ""), l7_proto=r.get("l7_proto", ""),
            bytes_sent=int(r.get("bytes_sent", 0) or 0),
            bytes_recv=int(r.get("bytes_recv", 0) or 0),
            packets_sent=int(r.get("packets_sent", 0) or 0),
            packets_recv=int(r.get("packets_recv", 0) or 0),
            l7_meta=r.get("l7_meta", ""), l7_category=r.get("l7_category", ""),
            duration_ms=int(r.get("duration_ms", 0) or 0),
            interface=r.get("interface", ""),
            dst_host=r.get("dst_host", ""),
            dst_country=r.get("dst_country", ""),
            dst_asn=int(r.get("dst_asn", 0) or 0),
            pcap_file=r.get("pcap_file", ""),
            risks=risks, risk_score=int(r.get("risk_score", 0) or 0),
        )

    # ── 安全/域名/应用/服务（简化实现）──────────────────

    async def query_security_events(
        self, since: datetime, min_score: int = 0, severity: str = "", limit: int = 100
    ) -> list[SecurityEvent]:
        return []  # 时序库聚合风险事件不友好；返回空（由 SQLite/ClickHouse 覆盖）

    async def query_security_overview(
        self, since: datetime, time_range: str = "1h"
    ) -> SecurityOverview:
        return SecurityOverview(time_range=time_range)

    async def query_top_domains(self, since: datetime, limit: int = 20) -> list[DomainStat]:
        span = max(60, int((datetime.now(timezone.utc) - since).total_seconds()))
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "bytes_sent" or r._field == "bytes_recv")
  |> group(columns:["dst_host"])
  |> sum(column:"_value")
  |> keep(columns:["dst_host", "_value"])
  |> sort(columns:["_value"], desc:true)
  |> limit(n:{limit})
'''
        rows = self._rows(await self._q(flux))
        total = sum(r.get("_value", 0) for r in rows) or 1
        return [DomainStat(host=r.get("dst_host", ""),
                           bytes_total=int(r.get("_value", 0)), flow_count=0,
                           percentage=round(r.get("_value", 0) / total * 100, 2))
                for r in rows if r.get("dst_host")]

    async def query_app_stats(self, since: datetime, limit: int = 20) -> list[AppStat]:
        span = max(60, int((datetime.now(timezone.utc) - since).total_seconds()))
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "bytes_sent" or r._field == "bytes_recv")
  |> group(columns:["l7_proto"])
  |> sum(column:"_value")
  |> keep(columns:["l7_proto", "_value"])
  |> sort(columns:["_value"], desc:true)
  |> limit(n:{limit})
'''
        rows = self._rows(await self._q(flux))
        total = sum(r.get("_value", 0) for r in rows) or 1
        return [AppStat(protocol=r.get("l7_proto", "unknown"),
                        bytes_total=int(r.get("_value", 0)), flow_count=0,
                        percentage=round(r.get("_value", 0) / total * 100, 2))
                for r in rows]

    async def query_traffic_totals(
        self, since: datetime, time_range: str = "5m"
    ) -> TrafficTotal:
        span = max(60, int((datetime.now(timezone.utc) - since).total_seconds()))
        b = self._bucket()
        flux = f'''
from(bucket:"{b}")
  |> range(start: -{span}s)
  |> filter(fn:(r)=> r._measurement == "{MEASUREMENT}")
  |> filter(fn:(r)=> r._field == "bytes_sent" or r._field == "bytes_recv")
  |> group()
  |> sum(column:"_value")
'''
        total_bytes = self._scalar(await self._q(flux))
        return TrafficTotal(
            total_bytes=int(total_bytes), total_packets=0, total_flows=0,
            by_protocol=[], by_category=[], time_range=time_range,
        )

    async def query_services_stats(self, since: datetime, limit: int = 20) -> list[ServiceStat]:
        return []

    async def query_device_profiles(
        self, since_ts: int, page: int = 1, size: int = 20,
        sort_by: str = "bytes", time_range: str = "1h",
    ) -> DeviceProfileList:
        return DeviceProfileList(devices=[], total=0, page=page, size=size)

    async def query_device_profile_detail(
        self, ip: str, since_ts: int, time_range: str = "1h"
    ) -> DeviceProfile | None:
        return None
