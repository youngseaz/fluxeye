"""ClickHouse 存储后端实现（基于 clickhouse-driver 的 AsyncClient）。

Schema 与 scripts/clickhouse_init.sql 对应，MergeTree 引擎 + 按天分区 + TTL
自动过期（保留期与 settings.storage.retention_days 对齐）。
所有查询走参数绑定，避免 SQL 注入。
"""

from __future__ import annotations

import asyncio
import itertools
import json
import logging
from datetime import datetime, timezone

from app.config import ClickHouseConfig
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


def _now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _time_range_seconds(time_range: str) -> int:
    """将时间范围字符串转为秒数（防注入：结果恒为整数）。"""
    try:
        unit = time_range[-1]
        value = int(time_range[:-1])
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        return value * multipliers.get(unit, 60)
    except (ValueError, TypeError, IndexError):
        return 60


def _dt(value) -> datetime | None:
    """将 ClickHouse 返回的时间值转 datetime。"""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


class ClickHouseStore(StorageBackend):
    """ClickHouse 存储后端。"""

    _COLUMNS = (
        "flow_id, timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, "
        "l4_proto, l7_proto, bytes_sent, bytes_recv, packets_sent, packets_recv, "
        "l7_meta, l7_category, duration_ms, interface, first_seen, last_seen, "
        "dst_host, dst_country, dst_region, dst_city, dst_asn, dst_as_org, "
        "dst_lat, dst_lon, pcap_file, risks, risk_score"
    )

    def __init__(self, config: ClickHouseConfig) -> None:
        self.config = config
        self._client = None
        self._available = False
        self._id_counter = itertools.count(1)

    # ── 连接/初始化 ──────────────────────────────────────

    async def initialize(self) -> None:
        try:
            from clickhouse_driver import Client
            self._client = Client(
                host=self.config.host,
                port=self.config.port,
                user=self.config.user,
                password=self.config.password,
                database=self.config.database,
            )
            await self._create_schema()
            # 初始化自增 ID（从现有最大 flow_id 继续）
            rows = await asyncio.to_thread(
                self._client.execute, "SELECT ifNull(max(flow_id), 0) FROM flows"
            )
            max_id = int(rows[0][0]) if rows else 0
            self._id_counter = itertools.count(max_id + 1)
            self._available = True
            logger.info("ClickHouse 存储已连接: %s:%s/%s",
                        self.config.host, self.config.port, self.config.database)
        except Exception as e:
            self._available = False
            logger.warning("ClickHouse 连接失败，存储不可用: %s", e)

    async def _create_schema(self) -> None:
        from app.config import settings
        retention_days = getattr(settings.storage, "retention_days", 7)
        await asyncio.to_thread(self._client.execute, f"""
            CREATE TABLE IF NOT EXISTS flows (
                flow_id UInt64,
                timestamp DateTime('UTC'),
                src_mac String DEFAULT '',
                dst_mac String DEFAULT '',
                src_ip String,
                dst_ip String,
                src_port UInt16,
                dst_port UInt16,
                l4_proto LowCardinality(String),
                l7_proto String,
                bytes_sent UInt64,
                bytes_recv UInt64,
                packets_sent UInt64,
                packets_recv UInt64,
                l7_meta String DEFAULT '',
                l7_category String DEFAULT '',
                duration_ms UInt32,
                interface String DEFAULT '',
                first_seen Nullable(DateTime('UTC')),
                last_seen Nullable(DateTime('UTC')),
                dst_host String DEFAULT '',
                dst_country String DEFAULT '',
                dst_region String DEFAULT '',
                dst_city String DEFAULT '',
                dst_asn UInt32 DEFAULT 0,
                dst_as_org String DEFAULT '',
                dst_lat Float64 DEFAULT 0,
                dst_lon Float64 DEFAULT 0,
                pcap_file String DEFAULT '',
                risks String DEFAULT '[]',
                risk_score UInt16 DEFAULT 0
            ) ENGINE = MergeTree()
            PARTITION BY toYYYYMMDD(timestamp)
            ORDER BY (timestamp, src_ip, dst_ip)
            TTL timestamp + INTERVAL {retention_days} DAY
        """)

    async def close(self) -> None:
        if self._client is not None:
            try:
                await asyncio.to_thread(self._client.disconnect)
            except Exception:
                pass
            self._client = None
        self._available = False

    # ── 写入 ────────────────────────────────────────────

    @staticmethod
    def _flow_to_row(flow: FlowRecord, flow_id: int) -> list:
        ts = flow.timestamp
        if not isinstance(ts, datetime):
            ts = datetime.fromtimestamp(ts.timestamp(), tz=timezone.utc)
        return [
            flow_id, ts, flow.src_mac, flow.dst_mac, flow.src_ip, flow.dst_ip,
            flow.src_port, flow.dst_port, flow.l4_proto, flow.l7_proto,
            flow.bytes_sent, flow.bytes_recv, flow.packets_sent, flow.packets_recv,
            flow.l7_meta, flow.l7_category, flow.duration_ms, flow.interface,
            flow.first_seen, flow.last_seen,
            flow.dst_host, flow.dst_country, flow.dst_region, flow.dst_city,
            flow.dst_asn, flow.dst_as_org, flow.dst_lat, flow.dst_lon,
            flow.pcap_file,
            json.dumps(flow.risks, ensure_ascii=False),
            flow.risk_score,
        ]

    async def write_flow(self, flow: FlowRecord) -> int:
        if not self._available or self._client is None:
            return 0
        flow_id = next(self._id_counter)
        await asyncio.to_thread(
            self._client.execute,
            f"INSERT INTO flows ({self._COLUMNS}) VALUES",
            [self._flow_to_row(flow, flow_id)],
        )
        return flow_id

    async def write_flows_batch(self, flows: list[FlowRecord]) -> int:
        if not self._available or self._client is None or not flows:
            return 0
        rows = [self._flow_to_row(f, next(self._id_counter)) for f in flows]
        await asyncio.to_thread(
            self._client.execute,
            f"INSERT INTO flows ({self._COLUMNS}) VALUES",
            rows,
        )
        return len(rows)

    # ── 查询辅助 ────────────────────────────────────────

    async def _q(self, sql: str, params: dict | None = None) -> list:
        """执行查询；存储不可用时返回空列表。"""
        if not self._available or self._client is None:
            return []
        try:
            return await asyncio.to_thread(self._client.execute, sql, params or {})
        except Exception as e:
            logger.error("ClickHouse 查询失败: %s | SQL: %.200s", e, sql)
            return []

    # ── 概览 ────────────────────────────────────────────

    async def query_overview(self, time_range: str = "5m") -> TrafficOverview:
        span = _time_range_seconds(time_range)
        since = _now_ts() - span
        rows = await self._q(
            """SELECT
                   toUInt64(sum(bytes_sent + bytes_recv)) AS total_bytes,
                   toUInt64(sum(packets_sent + packets_recv)) AS total_packets,
                   count() AS flow_count
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s""",
            {"since": since},
        )
        row = rows[0] if rows else (0, 0, 0)
        total_bytes, total_packets, flow_count = row
        return TrafficOverview(
            total_bps=total_bytes / span * 8 if span > 0 else 0,
            total_pps=total_packets / span if span > 0 else 0,
            active_flows=flow_count,
            total_connections=flow_count,
            time_range=time_range,
        )

    async def query_protocols(
        self, time_range: str = "1h", top: int = 10
    ) -> list[ProtocolStat]:
        span = _time_range_seconds(time_range)
        since = _now_ts() - span
        rows = await self._q(
            """SELECT l7_proto,
                      toUInt64(sum(bytes_sent + bytes_recv)) AS bytes_total,
                      count() AS flow_count
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY l7_proto ORDER BY bytes_total DESC LIMIT %(top)s""",
            {"since": since, "top": top},
        )
        total = sum(r[1] for r in rows) or 1
        return [ProtocolStat(l7_proto=r[0], bytes_total=r[1], flow_count=r[2],
                             percentage=round(r[1] / total * 100, 2)) for r in rows]

    async def query_top_talkers(
        self, top: int = 20, time_range: str = "30m"
    ) -> list[Talker]:
        span = _time_range_seconds(time_range)
        since = _now_ts() - span
        rows = await self._q(
            """SELECT src_ip AS ip, toUInt64(sum(bytes_sent)) AS bytes_total
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY src_ip ORDER BY bytes_total DESC LIMIT %(top)s""",
            {"since": since, "top": top},
        )
        talkers = [Talker(ip=r[0], bytes_total=r[1], direction="egress") for r in rows]
        rows2 = await self._q(
            """SELECT dst_ip AS ip, toUInt64(sum(bytes_recv)) AS bytes_total
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY dst_ip ORDER BY bytes_total DESC LIMIT %(top)s""",
            {"since": since, "top": top},
        )
        talkers += [Talker(ip=r[0], bytes_total=r[1], direction="ingress") for r in rows2]
        talkers.sort(key=lambda t: t.bytes_total, reverse=True)
        return talkers[:top]

    async def query_time_series(
        self, interval: str = "10s", time_range: str = "1h"
    ) -> list[TimePoint]:
        span = _time_range_seconds(time_range)
        interval_s = max(1, _time_range_seconds(interval))
        since = _now_ts() - span
        rows = await self._q(
            """SELECT toDateTime(intDiv(toUnixTimestamp(timestamp), %(iv)s) * %(iv)s) AS bucket,
                      toUInt64(sum(bytes_sent + bytes_recv)) AS bytes_total,
                      toUInt64(sum(packets_sent + packets_recv)) AS packets_total
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY bucket ORDER BY bucket""",
            {"iv": interval_s, "since": since},
        )
        return [TimePoint(
            timestamp=_dt(r[0]) or datetime.now(timezone.utc),
            bps=r[1] / interval_s * 8 if interval_s else 0,
            pps=r[2] / interval_s if interval_s else 0,
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
        conds = ["1=1"]
        params: dict = {}
        if l7_proto:
            conds.append("l7_proto = %(l7)s")
            params["l7"] = l7_proto
        if src_ip:
            conds.append("src_ip = %(src)s")
            params["src"] = src_ip
        if dst_ip:
            conds.append("dst_ip = %(dst)s")
            params["dst"] = dst_ip
        if time_start:
            conds.append("toUnixTimestamp(timestamp) >= %(ts_start)s")
            params["ts_start"] = int(time_start.timestamp())
        if time_end:
            conds.append("toUnixTimestamp(timestamp) <= %(ts_end)s")
            params["ts_end"] = int(time_end.timestamp())
        where = " AND ".join(conds)

        cnt_rows = await self._q(
            f"SELECT count() FROM flows WHERE {where}", params
        )
        total = int(cnt_rows[0][0]) if cnt_rows else 0
        qparams = dict(params)
        qparams["size"] = size
        qparams["offset"] = (page - 1) * size
        rows = await self._q(
            f"""SELECT flow_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                       l4_proto, l7_proto, bytes_sent, bytes_recv,
                       packets_sent, packets_recv, l7_meta, l7_category,
                       duration_ms, interface, dst_host, dst_country, dst_region,
                       dst_city, dst_asn, dst_as_org, dst_lat, dst_lon, pcap_file
                FROM flows WHERE {where}
                ORDER BY timestamp DESC LIMIT %(size)s OFFSET %(offset)s""",
            qparams,
        )
        items = [self._row_to_conversation(r) for r in rows]
        return Page(
            items=items, total=total, page=page, size=size,
            pages=(total + size - 1) // size if size else 0,
        )

    @staticmethod
    def _row_to_conversation(r) -> Conversation:
        return Conversation(
            id=int(r[0]),
            timestamp=_dt(r[1]) or datetime.now(timezone.utc),
            src_ip=r[2], dst_ip=r[3], src_port=r[4], dst_port=r[5],
            l4_proto=r[6], l7_proto=r[7],
            bytes_sent=r[8], bytes_recv=r[9], packets_sent=r[10], packets_recv=r[11],
            l7_meta=r[12], l7_category=r[13], duration_ms=r[14],
            interface=r[15], dst_host=r[16],
            dst_country=r[17], dst_region=r[18], dst_city=r[19],
            dst_asn=r[20], dst_as_org=r[21], dst_lat=r[22], dst_lon=r[23],
            pcap_file=r[24],
        )

    async def query_flow_by_id(self, flow_id: int) -> FlowRecord | None:
        rows = await self._q(
            """SELECT flow_id, timestamp, src_mac, dst_mac, src_ip, dst_ip,
                      src_port, dst_port, l4_proto, l7_proto,
                      bytes_sent, bytes_recv, packets_sent, packets_recv,
                      l7_meta, l7_category, duration_ms, interface,
                      first_seen, last_seen, dst_host, dst_country, dst_region,
                      dst_city, dst_asn, dst_as_org, dst_lat, dst_lon,
                      pcap_file, risks, risk_score
               FROM flows WHERE flow_id = %(fid)s LIMIT 1""",
            {"fid": flow_id},
        )
        if not rows:
            return None
        r = rows[0]
        try:
            risks = json.loads(r[29] or "[]")
        except (json.JSONDecodeError, TypeError):
            risks = []
        return FlowRecord(
            timestamp=_dt(r[1]) or datetime.now(timezone.utc),
            src_mac=r[2], dst_mac=r[3], src_ip=r[4], dst_ip=r[5],
            src_port=r[6], dst_port=r[7], l4_proto=r[8], l7_proto=r[9],
            bytes_sent=r[10], bytes_recv=r[11], packets_sent=r[12], packets_recv=r[13],
            l7_meta=r[14], l7_category=r[15], duration_ms=r[16], interface=r[17],
            first_seen=_dt(r[18]), last_seen=_dt(r[19]),
            dst_host=r[20], dst_country=r[21], dst_region=r[22], dst_city=r[23],
            dst_asn=r[24], dst_as_org=r[25], dst_lat=r[26], dst_lon=r[27],
            pcap_file=r[28], risks=risks, risk_score=r[30],
        )

    # ── 安全态势 ────────────────────────────────────────

    async def query_security_events(
        self, since: datetime, min_score: int = 0, severity: str = "", limit: int = 100
    ) -> list[SecurityEvent]:
        since_ts = int(since.timestamp())
        rows = await self._q(
            """SELECT timestamp, src_ip, dst_ip, src_port, dst_port, l4_proto,
                      l7_proto, risks, risk_score, bytes_sent, bytes_recv,
                      packets_sent, packets_recv, interface, dst_host,
                      dst_country, dst_city
               FROM flows
               WHERE toUnixTimestamp(timestamp) >= %(since)s AND risk_score > %(min)s
               ORDER BY risk_score DESC, timestamp DESC LIMIT %(limit)s""",
            {"since": since_ts, "min": min_score, "limit": limit},
        )
        events = []
        for r in rows:
            try:
                raw_risks = json.loads(r[7] or "[]")
            except (json.JSONDecodeError, TypeError):
                raw_risks = []
            details = [RiskDetail(
                id=rd.get("id", 0), name=rd.get("name", ""),
                severity=rd.get("severity", 0),
                severity_name=rd.get("severity_name", "unknown"),
                info=rd.get("info", ""),
            ) for rd in raw_risks]
            score = r[8]
            level = ""
            if details:
                sev_names = ["low", "medium", "high", "severe", "critical", "emergency"]
                max_sev = max(d.severity for d in details)
                level = sev_names[max_sev] if max_sev < len(sev_names) else "unknown"
            events.append(SecurityEvent(
                timestamp=_dt(r[0]) or datetime.now(timezone.utc),
                src_ip=r[1], dst_ip=r[2], src_port=r[3], dst_port=r[4],
                l4_proto=r[5], l7_proto=r[6], risks=details, risk_score=score,
                risk_level=level,
                bytes_total=(r[9] or 0) + (r[10] or 0),
                packets_total=(r[11] or 0) + (r[12] or 0),
                interface=r[13], dst_host=r[14], dst_country=r[15], dst_city=r[16],
            ))
        return events

    async def query_security_overview(
        self, since: datetime, time_range: str = "1h"
    ) -> SecurityOverview:
        since_ts = int(since.timestamp())
        row = await self._q(
            """SELECT count() AS total,
                      ifNull(sum(risk_score), 0) AS score,
                      countIf(risk_score >= 200) AS critical_count,
                      countIf(risk_score >= 100 AND risk_score < 200) AS high_count,
                      countIf(risk_score >= 10 AND risk_score < 100) AS medium_count,
                      countIf(risk_score > 0 AND risk_score < 10) AS low_count
               FROM flows
               WHERE toUnixTimestamp(timestamp) >= %(since)s AND risk_score > 0""",
            {"since": since_ts},
        )
        r = row[0] if row else (0, 0, 0, 0, 0, 0)
        total, _, crit, high, med, low = r
        rows2 = await self._q(
            """SELECT l7_proto, count() AS cnt FROM flows
               WHERE toUnixTimestamp(timestamp) >= %(since)s AND risk_score > 0
               GROUP BY l7_proto ORDER BY cnt DESC LIMIT 10""",
            {"since": since_ts},
        )
        top_risks = [{"name": rr[0], "count": rr[1]} for rr in rows2]
        return SecurityOverview(
            total_events=total, critical_count=crit, high_count=high,
            medium_count=med, low_count=low, top_risks=top_risks,
            by_severity=[
                {"severity": "critical", "count": crit},
                {"severity": "high", "count": high},
                {"severity": "medium", "count": med},
                {"severity": "low", "count": low},
            ],
            time_range=time_range,
        )

    # ── 域名/应用/总量/服务 ─────────────────────────────

    async def query_top_domains(self, since: datetime, limit: int = 20) -> list[DomainStat]:
        since_ts = int(since.timestamp())
        rows = await self._q(
            """SELECT dst_host, toUInt64(sum(bytes_sent + bytes_recv)) AS b, count() AS c
               FROM flows
               WHERE toUnixTimestamp(timestamp) >= %(since)s AND dst_host != ''
               GROUP BY dst_host ORDER BY b DESC LIMIT %(limit)s""",
            {"since": since_ts, "limit": limit},
        )
        total = sum(r[1] for r in rows) or 1
        return [DomainStat(host=r[0], bytes_total=r[1], flow_count=r[2],
                           percentage=round(r[1] / total * 100, 2)) for r in rows]

    async def query_app_stats(self, since: datetime, limit: int = 20) -> list[AppStat]:
        since_ts = int(since.timestamp())
        rows = await self._q(
            """SELECT l7_proto, toUInt64(sum(bytes_sent + bytes_recv)) AS b, count() AS c
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY l7_proto ORDER BY b DESC LIMIT %(limit)s""",
            {"since": since_ts, "limit": limit},
        )
        total = sum(r[1] for r in rows) or 1
        return [AppStat(protocol=r[0], bytes_total=r[1], flow_count=r[2],
                        percentage=round(r[1] / total * 100, 2)) for r in rows]

    async def query_traffic_totals(
        self, since: datetime, time_range: str = "5m"
    ) -> TrafficTotal:
        since_ts = int(since.timestamp())
        row = await self._q(
            """SELECT ifNull(sum(bytes_sent + bytes_recv), 0),
                      ifNull(sum(packets_sent + packets_recv), 0), count()
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s""",
            {"since": since_ts},
        )
        r = row[0] if row else (0, 0, 0)
        rows2 = await self._q(
            """SELECT l7_proto, toUInt64(sum(bytes_sent + bytes_recv)) AS b
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY l7_proto ORDER BY b DESC""",
            {"since": since_ts},
        )
        rows3 = await self._q(
            """SELECT l7_category, toUInt64(sum(bytes_sent + bytes_recv)) AS b
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s AND l7_category != ''
               GROUP BY l7_category ORDER BY b DESC""",
            {"since": since_ts},
        )
        return TrafficTotal(
            total_bytes=r[0], total_packets=r[1], total_flows=r[2],
            by_protocol=[{"protocol": x[0], "bytes": x[1]} for x in rows2],
            by_category=[{"category": x[0], "bytes": x[1]} for x in rows3],
            time_range=time_range,
        )

    async def query_services_stats(self, since: datetime, limit: int = 20) -> list[ServiceStat]:
        since_ts = int(since.timestamp())
        rows = await self._q(
            """SELECT l7_proto, dst_host, l7_category,
                      toUInt64(sum(bytes_sent + bytes_recv)) AS b, count() AS c
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY l7_proto, dst_host ORDER BY b DESC""",
            {"since": since_ts},
        )
        service_map: dict[str, dict] = {}
        for r in rows:
            proto, host, cat, b, c = r
            svc = SQLiteStore._map_service(proto, host)
            if svc not in service_map:
                service_map[svc] = {"bytes": 0, "flows": 0, "cat": cat or ""}
            service_map[svc]["bytes"] += b
            service_map[svc]["flows"] += c
            if not service_map[svc]["cat"] and cat:
                service_map[svc]["cat"] = cat
        total = sum(v["bytes"] for v in service_map.values()) or 1
        sorted_items = sorted(service_map.items(), key=lambda x: -x[1]["bytes"])
        return [ServiceStat(
            service=svc, bytes_total=info["bytes"], flow_count=info["flows"],
            percentage=round(info["bytes"] / total * 100, 2), category=info["cat"],
        ) for svc, info in sorted_items[:limit]]

    # ── 设备画像 ────────────────────────────────────────

    async def query_device_profiles(
        self, since_ts: int, page: int = 1, size: int = 20,
        sort_by: str = "bytes", time_range: str = "1h",
    ) -> DeviceProfileList:
        order_map = {
            "bytes": "total_bytes DESC",
            "flows": "flow_count DESC",
            "last_seen": "last_seen DESC",
            "risk": "risk_score DESC",
        }
        order = order_map.get(sort_by, "total_bytes DESC")
        rows = await self._q(
            f"""SELECT
                     if(src_mac != '', src_mac, src_ip) AS device_id,
                     max(src_mac) AS src_mac,
                     argMax(src_ip, timestamp) AS src_ip,
                     toUInt64(sum(bytes_sent)) AS bytes_sent,
                     toUInt64(sum(bytes_recv)) AS bytes_recv,
                     toUInt64(sum(packets_sent)) AS packets_sent,
                     toUInt64(sum(packets_recv)) AS packets_recv,
                     toUInt64(sum(bytes_sent + bytes_recv)) AS total_bytes,
                     count() AS flow_count,
                     min(timestamp) AS first_seen,
                     max(timestamp) AS last_seen,
                     max(risk_score) AS risk_score
               FROM flows WHERE toUnixTimestamp(timestamp) >= %(since)s
               GROUP BY device_id ORDER BY {order}""",
            {"since": since_ts},
        )
        total = len(rows)
        page_rows = rows[(page - 1) * size: (page - 1) * size + size]
        devices = []
        for r in page_rows:
            mac = r[1] or ""
            from app.geo.mac_vendor import lookup_vendor, vendor_alias
            devices.append(DeviceProfile(
                mac=mac,
                ip=r[2],
                vendor=vendor_alias(lookup_vendor(mac)) if mac else "",
                bytes_sent=r[3], bytes_recv=r[4],
                packets_sent=r[5], packets_recv=r[6],
                flow_count=r[7],
                first_seen=_dt(r[8]), last_seen=_dt(r[9]),
                risk_score=r[10],
                risk_events=1 if r[10] > 0 else 0,
            ))
        return DeviceProfileList(devices=devices, total=total, page=page, size=size)

    async def query_device_profile_detail(
        self, ip: str, since_ts: int, time_range: str = "1h"
    ) -> DeviceProfile | None:
        is_mac = ":" in ip or "-" in ip
        col = "src_mac" if is_mac else "src_ip"
        rows = await self._q(
            f"""SELECT max(src_mac), argMax(src_ip, timestamp),
                      toUInt64(sum(bytes_sent)), toUInt64(sum(bytes_recv)),
                      toUInt64(sum(packets_sent)), toUInt64(sum(packets_recv)),
                      count(), min(timestamp), max(timestamp), max(risk_score)
               FROM flows
               WHERE toUnixTimestamp(timestamp) >= %(since)s AND {col} = %(ip)s""",
            {"since": since_ts, "ip": ip},
        )
        if not rows:
            return None
        r = rows[0]
        mac = r[0] or ""
        from app.geo.mac_vendor import lookup_vendor, vendor_alias
        return DeviceProfile(
            mac=mac, ip=r[1],
            vendor=vendor_alias(lookup_vendor(mac)) if mac else "",
            bytes_sent=r[2], bytes_recv=r[3],
            packets_sent=r[4], packets_recv=r[5],
            flow_count=r[6],
            first_seen=_dt(r[7]), last_seen=_dt(r[8]),
            risk_score=r[9], risk_events=1 if r[9] > 0 else 0,
        )

    # ── 维护 ────────────────────────────────────────────

    async def cleanup_old_flows(self, retention_days: int = 7) -> int:
        # ClickHouse 使用表 TTL 自动过期，无需手动清理
        return 0
