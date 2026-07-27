"""SQLite 存储后端实现 — 默认存储引擎。"""

from __future__ import annotations

import json
import math
import sqlite3
from datetime import datetime
from pathlib import Path

import aiosqlite

from app.config import SQLiteConfig
from app.utils.logger import get_logger

logger = get_logger("storage.sqlite")
from app.models.schemas import (
    AppStat,
    Conversation,
    DeviceProfile,
    DeviceProfileList,
    DomainStat,
    FlowRecord,
    Page,
    PeerStat,
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


class SQLiteStore(StorageBackend):
    """SQLite 存储后端，使用 WAL 模式优化写入性能。"""

    def __init__(self, config: SQLiteConfig) -> None:
        self.config = config
        self.db_path = Path(config.path)
        self._conn: aiosqlite.Connection | None = None

    # ── 生命周期 ────────────────────────────────────────

    async def initialize(self) -> None:
        """初始化数据库连接，创建表结构。"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(str(self.db_path))
        self._conn.row_factory = aiosqlite.Row

        if self.config.wal:
            await self._conn.execute("PRAGMA journal_mode=WAL;")
        await self._conn.execute(
            f"PRAGMA journal_size_limit={self.config.journal_size_limit};"
        )
        await self._conn.execute("PRAGMA synchronous=NORMAL;")
        await self._conn.execute("PRAGMA cache_size=-8000;")  # 8 MB cache

        await self._create_tables()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _create_tables(self) -> None:
        """创建 SQLite 表结构和索引（含自动迁移）。"""
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp_s INTEGER NOT NULL,
                src_mac TEXT DEFAULT '',
                dst_mac TEXT DEFAULT '',
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                l4_proto TEXT NOT NULL,
                l7_proto TEXT NOT NULL DEFAULT 'unknown',
                bytes_sent INTEGER DEFAULT 0,
                bytes_recv INTEGER DEFAULT 0,
                packets_sent INTEGER DEFAULT 0,
                packets_recv INTEGER DEFAULT 0,
                l7_meta TEXT DEFAULT '',
                duration_ms INTEGER DEFAULT 0,
                dst_country TEXT DEFAULT '',
                dst_region TEXT DEFAULT '',
                dst_city TEXT DEFAULT '',
                dst_asn INTEGER DEFAULT 0,
                dst_as_org TEXT DEFAULT '',
                dst_lat REAL DEFAULT 0.0,
                dst_lon REAL DEFAULT 0.0,
                dst_host TEXT DEFAULT '',
                interface TEXT DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(timestamp_s);
            CREATE INDEX IF NOT EXISTS idx_flows_l7 ON flows(l7_proto);
            CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
            CREATE INDEX IF NOT EXISTS idx_flows_dst ON flows(dst_ip);

            CREATE TABLE IF NOT EXISTS proto_stats (
                time_bucket INTEGER NOT NULL,
                l7_proto TEXT NOT NULL,
                bytes_total INTEGER DEFAULT 0,
                flow_count INTEGER DEFAULT 0,
                PRIMARY KEY (time_bucket, l7_proto)
            );

            CREATE INDEX IF NOT EXISTS idx_proto_stats_bucket
                ON proto_stats(time_bucket);

            CREATE TABLE IF NOT EXISTS top_talkers (
                time_bucket INTEGER NOT NULL,
                ip TEXT NOT NULL,
                bytes_total INTEGER DEFAULT 0,
                direction TEXT NOT NULL,
                PRIMARY KEY (time_bucket, ip, direction)
            );

            CREATE INDEX IF NOT EXISTS idx_top_talkers_bucket
                ON top_talkers(time_bucket);
        """)
        # 自动迁移：为旧数据库添加缺失的 GeoIP 列
        migrations = [
            "ALTER TABLE flows ADD COLUMN dst_country TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN dst_city TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN dst_asn INTEGER DEFAULT 0",
            "ALTER TABLE flows ADD COLUMN dst_as_org TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN dst_lat REAL DEFAULT 0.0",
            "ALTER TABLE flows ADD COLUMN dst_lon REAL DEFAULT 0.0",
            "ALTER TABLE flows ADD COLUMN dst_region TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN dst_host TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN interface TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN src_mac TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN dst_mac TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN risks TEXT DEFAULT '[]'",
            "ALTER TABLE flows ADD COLUMN risk_score INTEGER DEFAULT 0",
            "ALTER TABLE flows ADD COLUMN l7_category TEXT DEFAULT ''",
            "ALTER TABLE flows ADD COLUMN pcap_file TEXT DEFAULT ''",
        ]
        for sql in migrations:
            try:
                await self._conn.execute(sql)
                logger.info("数据库迁移: %s", sql)
            except Exception:
                pass  # 列已存在时忽略
        await self._conn.commit()

    # ── 写入 ────────────────────────────────────────────

    async def write_flow(self, flow: FlowRecord) -> int:
        assert self._conn is not None
        logger.debug("写入流: %s:%d → %s:%d [%s] bytes=%d",
                     flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
                     flow.l7_proto, flow.bytes_sent + flow.bytes_recv)
        ts = int(flow.timestamp.timestamp())
        risks_json = json.dumps(flow.risks, ensure_ascii=False)
        cursor = await self._conn.execute(
            """INSERT INTO flows
               (timestamp_s, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                l4_proto, l7_proto, bytes_sent, bytes_recv,
                packets_sent, packets_recv, l7_meta, duration_ms, l7_category,
                dst_country, dst_region, dst_city, dst_asn, dst_as_org, dst_lat, dst_lon,
                dst_host, interface, risks, risk_score, pcap_file)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ts,
                flow.src_mac,
                flow.dst_mac,
                flow.src_ip,
                flow.dst_ip,
                flow.src_port,
                flow.dst_port,
                flow.l4_proto,
                flow.l7_proto,
                flow.bytes_sent,
                flow.bytes_recv,
                flow.packets_sent,
                flow.packets_recv,
                flow.l7_meta,
                flow.duration_ms,
                flow.l7_category,
                flow.dst_country,
                flow.dst_region,
                flow.dst_city,
                flow.dst_asn,
                flow.dst_as_org,
                flow.dst_lat,
                flow.dst_lon,
                flow.dst_host,
                flow.interface,
                risks_json,
                flow.risk_score,
                flow.pcap_file,
            ),
        )
        await self._conn.commit()
        return cursor.lastrowid or 0

    async def write_flows_batch(self, flows: list[FlowRecord]) -> int:
        assert self._conn is not None
        if not flows:
            return 0
        logger.debug("批量写入 %d 条流记录", len(flows))
        rows = [
            (
                int(f.timestamp.timestamp()),
                f.src_mac,
                f.dst_mac,
                f.src_ip,
                f.dst_ip,
                f.src_port,
                f.dst_port,
                f.l4_proto,
                f.l7_proto,
                f.bytes_sent,
                f.bytes_recv,
                f.packets_sent,
                f.packets_recv,
                f.l7_meta,
                f.duration_ms,
                f.l7_category,
                f.dst_country,
                f.dst_region,
                f.dst_city,
                f.dst_asn,
                f.dst_as_org,
                f.dst_lat,
                f.dst_lon,
                f.dst_host,
                f.interface,
                json.dumps(f.risks, ensure_ascii=False),
                f.risk_score,
                f.pcap_file,
            )
            for f in flows
        ]
        await self._conn.executemany(
            """INSERT INTO flows
               (timestamp_s, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                l4_proto, l7_proto, bytes_sent, bytes_recv,
                packets_sent, packets_recv, l7_meta, duration_ms, l7_category,
                dst_country, dst_region, dst_city, dst_asn, dst_as_org, dst_lat, dst_lon,
                dst_host, interface, risks, risk_score, pcap_file)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        await self._conn.commit()
        return len(rows)

    async def _get_time_range_seconds(self, time_range: str) -> int:
        """将时间范围字符串转为秒数。"""
        unit = time_range[-1]
        value = int(time_range[:-1])
        multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        return value * multipliers.get(unit, 60)

    # ── 查询 ────────────────────────────────────────────

    async def query_overview(self, time_range: str = "5m") -> TrafficOverview:
        assert self._conn is not None
        span = await self._get_time_range_seconds(time_range)
        now = int(datetime.now().timestamp())
        since = now - span
        logger.debug("查询概览: time_range=%s span=%ds", time_range, span)

        cursor = await self._conn.execute(
            """SELECT
                   COALESCE(SUM(bytes_sent + bytes_recv), 0) AS total_bytes,
                   COALESCE(SUM(packets_sent + packets_recv), 0) AS total_packets,
                   COUNT(*) AS flow_count
               FROM flows WHERE timestamp_s >= ?""",
            (since,),
        )
        row = await cursor.fetchone()
        total_bytes = row["total_bytes"] if row else 0
        total_packets = row["total_packets"] if row else 0
        flow_count = row["flow_count"] if row else 0

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
        assert self._conn is not None
        span = await self._get_time_range_seconds(time_range)
        now = int(datetime.now().timestamp())
        since = now - span

        cursor = await self._conn.execute(
            """SELECT l7_proto,
                      SUM(bytes_sent + bytes_recv) AS bytes_total,
                      COUNT(*) AS flow_count
               FROM flows
               WHERE timestamp_s >= ?
               GROUP BY l7_proto
               ORDER BY bytes_total DESC
               LIMIT ?""",
            (since, top),
        )
        rows = await cursor.fetchall()
        total = sum(r["bytes_total"] for r in rows) if rows else 1

        return [
            ProtocolStat(
                l7_proto=r["l7_proto"],
                bytes_total=r["bytes_total"],
                flow_count=r["flow_count"],
                percentage=round(r["bytes_total"] / total * 100, 2),
            )
            for r in rows
        ]

    async def query_top_talkers(
        self, top: int = 20, time_range: str = "30m"
    ) -> list[Talker]:
        assert self._conn is not None
        span = await self._get_time_range_seconds(time_range)
        now = int(datetime.now().timestamp())
        since = now - span

        # 出方向: 本机(src_ip)主动发起的流量
        cursor = await self._conn.execute(
            """SELECT src_ip AS ip,
                      SUM(bytes_sent) AS bytes_total
               FROM flows
               WHERE timestamp_s >= ?
               GROUP BY src_ip
               ORDER BY bytes_total DESC
               LIMIT ?""",
            (since, top),
        )
        egress = [
            Talker(ip=r["ip"], bytes_total=r["bytes_total"], direction="egress")
            for r in await cursor.fetchall()
        ]

        # 入方向: 远端(dst_ip)发回的流量
        cursor = await self._conn.execute(
            """SELECT dst_ip AS ip,
                      SUM(bytes_recv) AS bytes_total
               FROM flows
               WHERE timestamp_s >= ?
               GROUP BY dst_ip
               ORDER BY bytes_total DESC
               LIMIT ?""",
            (since, top),
        )
        ingress = [
            Talker(ip=r["ip"], bytes_total=r["bytes_total"], direction="ingress")
            for r in await cursor.fetchall()
        ]

        # 合并，按流量降序排列
        talkers = egress + ingress
        talkers.sort(key=lambda t: t.bytes_total, reverse=True)
        return talkers[:top]

    async def query_time_series(
        self, interval: str = "10s", time_range: str = "1h"
    ) -> list[TimePoint]:
        assert self._conn is not None
        span = await self._get_time_range_seconds(time_range)
        interval_s = await self._get_time_range_seconds(interval)
        now = int(datetime.now().timestamp())
        since = now - span

        cursor = await self._conn.execute(
            """SELECT
                   (timestamp_s / ?) * ? AS bucket,
                   SUM(bytes_sent + bytes_recv) AS bytes_total,
                   SUM(packets_sent + packets_recv) AS packets_total
               FROM flows
               WHERE timestamp_s >= ?
               GROUP BY bucket
               ORDER BY bucket ASC""",
            (interval_s, interval_s, since),
        )
        rows = await cursor.fetchall()
        return [
            TimePoint(
                timestamp=datetime.fromtimestamp(r["bucket"]),
                bps=r["bytes_total"] / interval_s * 8 if interval_s > 0 else 0,
                pps=r["packets_total"] / interval_s if interval_s > 0 else 0,
            )
            for r in rows
        ]

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
        assert self._conn is not None

        conditions = ["1=1"]
        params: list = []

        if l7_proto:
            conditions.append("l7_proto = ?")
            params.append(l7_proto)
        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)
        if dst_ip:
            conditions.append("dst_ip = ?")
            params.append(dst_ip)
        if time_start:
            conditions.append("timestamp_s >= ?")
            params.append(int(time_start.timestamp()))
        if time_end:
            conditions.append("timestamp_s <= ?")
            params.append(int(time_end.timestamp()))

        where = " AND ".join(conditions)

        # 总数
        cursor = await self._conn.execute(
            f"SELECT COUNT(*) AS cnt FROM flows WHERE {where}", params
        )
        row = await cursor.fetchone()
        total = row["cnt"] if row else 0

        # 分页
        offset = (page - 1) * size
        cursor = await self._conn.execute(
            f"""SELECT * FROM flows
                WHERE {where}
                ORDER BY timestamp_s DESC
                LIMIT ? OFFSET ?""",
            [*params, size, offset],
        )
        rows = await cursor.fetchall()

        items = [
            Conversation(
                id=r["id"],
                timestamp=datetime.fromtimestamp(r["timestamp_s"]),
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                src_port=r["src_port"],
                dst_port=r["dst_port"],
                l4_proto=r["l4_proto"],
                l7_proto=r["l7_proto"],
                bytes_sent=r["bytes_sent"],
                bytes_recv=r["bytes_recv"],
                packets_sent=r["packets_sent"],
                packets_recv=r["packets_recv"],
                l7_meta=r["l7_meta"],
                duration_ms=r["duration_ms"],
                dst_country=r["dst_country"] if "dst_country" in r.keys() else "",
                dst_region=r["dst_region"] if "dst_region" in r.keys() else "",
                dst_city=r["dst_city"] if "dst_city" in r.keys() else "",
                dst_asn=r["dst_asn"] if "dst_asn" in r.keys() else 0,
                dst_as_org=r["dst_as_org"] if "dst_as_org" in r.keys() else "",
                dst_lat=r["dst_lat"] if "dst_lat" in r.keys() else 0.0,
                dst_lon=r["dst_lon"] if "dst_lon" in r.keys() else 0.0,
                dst_host=r["dst_host"] if "dst_host" in r.keys() else "",
                first_seen=None,
                last_seen=None,
                interface=r["interface"] if "interface" in r.keys() else "",
            )
            for r in rows
        ]

        return Page(
            items=items,
            total=total,
            page=page,
            size=size,
            pages=max(1, math.ceil(total / size)),
        )

    async def query_flow_by_id(self, flow_id: int) -> FlowRecord | None:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM flows WHERE id = ?", (flow_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        risks_data = json.loads(row["risks"]) if "risks" in row.keys() and row["risks"] else []
        risk_score_val = row["risk_score"] if "risk_score" in row.keys() else 0
        return FlowRecord(
            timestamp=datetime.fromtimestamp(row["timestamp_s"]),
            src_mac=row["src_mac"] if "src_mac" in row.keys() else "",
            dst_mac=row["dst_mac"] if "dst_mac" in row.keys() else "",
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            src_port=row["src_port"],
            dst_port=row["dst_port"],
            l4_proto=row["l4_proto"],
            l7_proto=row["l7_proto"],
            bytes_sent=row["bytes_sent"],
            bytes_recv=row["bytes_recv"],
            packets_sent=row["packets_sent"],
            packets_recv=row["packets_recv"],
            l7_meta=row["l7_meta"],
            duration_ms=row["duration_ms"],
            dst_country=row["dst_country"] if "dst_country" in row.keys() else "",
            dst_region=row["dst_region"] if "dst_region" in row.keys() else "",
            dst_city=row["dst_city"] if "dst_city" in row.keys() else "",
            dst_asn=row["dst_asn"] if "dst_asn" in row.keys() else 0,
            dst_as_org=row["dst_as_org"] if "dst_as_org" in row.keys() else "",
            dst_lat=row["dst_lat"] if "dst_lat" in row.keys() else 0.0,
            dst_lon=row["dst_lon"] if "dst_lon" in row.keys() else 0.0,
            dst_host=row["dst_host"] if "dst_host" in row.keys() else "",
            first_seen=None,
            last_seen=None,
            interface=row["interface"] if "interface" in row.keys() else "",
            risks=risks_data,
            risk_score=risk_score_val,
            pcap_file=row["pcap_file"] if "pcap_file" in row.keys() else "",
        )

    # ── 维护 ────────────────────────────────────────────

    async def cleanup_old_flows(self, retention_days: int = 7) -> int:
        """清理超过 retention_days 的旧流记录。

        聚合到 proto_stats / top_talkers 后删除原始明细。
        每小时和每天的聚合数据保留更久，由外部调度负责。
        """
        assert self._conn is not None
        import time
        cutoff = int(time.time()) - retention_days * 86_400

        # 先聚合到小时级统计（保留原始协议分布信息）
        await self._conn.execute("""
            INSERT OR IGNORE INTO proto_stats (time_bucket, l7_proto, bytes_total, flow_count)
            SELECT
                (timestamp_s / 3600) * 3600 AS bucket,
                l7_proto,
                SUM(bytes_sent + bytes_recv),
                COUNT(*)
            FROM flows
            WHERE timestamp_s < ?
            GROUP BY bucket, l7_proto
        """, (cutoff,))

        # 聚合到 top_talkers
        await self._conn.execute("""
            INSERT OR IGNORE INTO top_talkers (time_bucket, ip, bytes_total, direction)
            SELECT
                (timestamp_s / 3600) * 3600 AS bucket,
                src_ip, SUM(bytes_sent), 'egress'
            FROM flows WHERE timestamp_s < ?
            GROUP BY bucket, src_ip
        """, (cutoff,))
        await self._conn.execute("""
            INSERT OR IGNORE INTO top_talkers (time_bucket, ip, bytes_total, direction)
            SELECT
                (timestamp_s / 3600) * 3600 AS bucket,
                dst_ip, SUM(bytes_recv), 'ingress'
            FROM flows WHERE timestamp_s < ?
            GROUP BY bucket, dst_ip
        """, (cutoff,))

        # 删除旧明细
        cursor = await self._conn.execute(
            "DELETE FROM flows WHERE timestamp_s < ?", (cutoff,)
        )
        deleted = cursor.rowcount
        await self._conn.commit()

        if deleted > 0:
            logger.info("数据保留: 已清理 %d 条超过 %d 天的旧流记录",
                        deleted, retention_days)
            # 清理后重新整理数据库
            await self._conn.execute("PRAGMA optimize;")

        return deleted

    # ── 安全态势 ────────────────────────────────────────

    async def query_security_events(
        self,
        since: datetime,
        min_score: int = 0,
        severity: str = "",
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """查询安全事件（含风险信息的流记录）。"""
        assert self._conn is not None
        since_ts = int(since.timestamp())

        # 如果有风险列存在，查询有风险的流
        cursor = await self._conn.execute(
            """SELECT * FROM flows
               WHERE timestamp_s >= ?
                 AND risk_score > ?
               ORDER BY risk_score DESC, timestamp_s DESC
               LIMIT ?""",
            (since_ts, min_score, limit),
        )
        rows = await cursor.fetchall()
        events: list[SecurityEvent] = []
        for r in rows:
            risks_data = []
            try:
                raw = r["risks"] if "risks" in r.keys() else "[]"
                if raw:
                    risks_data = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                risks_data = []

            risk_details = []
            for rd in risks_data:
                risk_details.append(RiskDetail(
                    id=rd.get("id", 0),
                    name=rd.get("name", f"risk_{rd.get('id', 0)}"),
                    severity=rd.get("severity", 0),
                    severity_name=rd.get("severity_name", "unknown"),
                    info=rd.get("info", ""),
                ))

            risk_score = r["risk_score"] if "risk_score" in r.keys() else 0
            risk_level = ""
            if risk_details:
                max_sev = max(rd.severity for rd in risk_details)
                sev_names = ["low", "medium", "high", "severe", "critical", "emergency"]
                risk_level = sev_names[max_sev] if max_sev < len(sev_names) else "unknown"

            events.append(SecurityEvent(
                timestamp=datetime.fromtimestamp(r["timestamp_s"]),
                src_ip=r["src_ip"],
                dst_ip=r["dst_ip"],
                src_port=r["src_port"],
                dst_port=r["dst_port"],
                l4_proto=r["l4_proto"],
                l7_proto=r["l7_proto"],
                risks=risk_details,
                risk_score=risk_score,
                risk_level=risk_level,
                bytes_total=(r["bytes_sent"] + r["bytes_recv"]),
                packets_total=(r["packets_sent"] + r["packets_recv"]),
                interface=r["interface"] if "interface" in r.keys() else "",
                dst_host=r["dst_host"] if "dst_host" in r.keys() else "",
                dst_country=r["dst_country"] if "dst_country" in r.keys() else "",
                dst_city=r["dst_city"] if "dst_city" in r.keys() else "",
            ))
        return events

    async def query_security_overview(
        self,
        since: datetime,
        time_range: str = "1h",
    ) -> SecurityOverview:
        """查询安全态势概览统计。"""
        assert self._conn is not None
        since_ts = int(since.timestamp())

        cursor = await self._conn.execute(
            """SELECT
                   COUNT(*) AS total,
                   COALESCE(SUM(risk_score), 0) AS total_score,
                   COUNT(CASE WHEN risk_score >= 200 THEN 1 END) AS critical_count,
                   COUNT(CASE WHEN risk_score >= 100 AND risk_score < 200 THEN 1 END) AS high_count,
                   COUNT(CASE WHEN risk_score >= 10 AND risk_score < 100 THEN 1 END) AS medium_count,
                   COUNT(CASE WHEN risk_score > 0 AND risk_score < 10 THEN 1 END) AS low_count
               FROM flows
               WHERE timestamp_s >= ? AND risk_score > 0""",
            (since_ts,),
        )
        row = await cursor.fetchone()
        total = row["total"] if row else 0
        critical = row["critical_count"] if row else 0
        high = row["high_count"] if row else 0
        medium = row["medium_count"] if row else 0
        low = row["low_count"] if row else 0

        # 按风险类型统计
        cursor2 = await self._conn.execute(
            """SELECT l7_proto, COUNT(*) AS cnt
               FROM flows
               WHERE timestamp_s >= ? AND risk_score > 0
               GROUP BY l7_proto
               ORDER BY cnt DESC
               LIMIT 10""",
            (since_ts,),
        )
        top_rows = await cursor2.fetchall()
        top_risks = [{"name": r["l7_proto"], "count": r["cnt"]} for r in top_rows]

        # 按严重级别统计
        by_severity = [
            {"severity": "critical", "count": critical},
            {"severity": "high", "count": high},
            {"severity": "medium", "count": medium},
            {"severity": "low", "count": low},
        ]

        return SecurityOverview(
            total_events=total,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            top_risks=top_risks,
            by_severity=by_severity,
            time_range=time_range,
        )

    # ── 域名统计 ────────────────────────────────────────

    async def query_top_domains(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[DomainStat]:
        """查询 Top N 访问域名（按流量排序）。"""
        assert self._conn is not None
        since_ts = int(since.timestamp())
        cursor = await self._conn.execute(
            """SELECT dst_host AS host,
                      SUM(bytes_sent + bytes_recv) AS bytes_total,
                      COUNT(*) AS flow_count
               FROM flows
               WHERE timestamp_s >= ? AND dst_host != '' AND dst_host IS NOT NULL
               GROUP BY dst_host
               ORDER BY bytes_total DESC
               LIMIT ?""",
            (since_ts, limit),
        )
        rows = await cursor.fetchall()
        total = sum(r["bytes_total"] for r in rows) if rows else 1
        return [
            DomainStat(
                host=r["host"],
                bytes_total=r["bytes_total"],
                flow_count=r["flow_count"],
                percentage=round(r["bytes_total"] / total * 100, 2),
            )
            for r in rows
        ]

    # ── 应用统计 ────────────────────────────────────────

    async def query_app_stats(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[AppStat]:
        """查询应用层协议统计（按流量排序）。"""
        assert self._conn is not None
        since_ts = int(since.timestamp())
        cursor = await self._conn.execute(
            """SELECT l7_proto AS protocol,
                      SUM(bytes_sent + bytes_recv) AS bytes_total,
                      COUNT(*) AS flow_count
               FROM flows
               WHERE timestamp_s >= ?
               GROUP BY l7_proto
               ORDER BY bytes_total DESC
               LIMIT ?""",
            (since_ts, limit),
        )
        rows = await cursor.fetchall()
        total = sum(r["bytes_total"] for r in rows) if rows else 1
        return [
            AppStat(
                protocol=r["protocol"],
                bytes_total=r["bytes_total"],
                flow_count=r["flow_count"],
                percentage=round(r["bytes_total"] / total * 100, 2),
            )
            for r in rows
        ]

    # ── 流量总和 ────────────────────────────────────────

    async def query_traffic_totals(
        self,
        since: datetime,
        time_range: str = "5m",
    ) -> TrafficTotal:
        """查询流量总和统计。"""
        assert self._conn is not None
        since_ts = int(since.timestamp())

        cursor = await self._conn.execute(
            """SELECT
                   COALESCE(SUM(bytes_sent + bytes_recv), 0) AS total_bytes,
                   COALESCE(SUM(packets_sent + packets_recv), 0) AS total_packets,
                   COUNT(*) AS total_flows
               FROM flows WHERE timestamp_s >= ?""",
            (since_ts,),
        )
        row = await cursor.fetchone()
        total_bytes = row["total_bytes"] if row else 0
        total_packets = row["total_packets"] if row else 0
        total_flows = row["total_flows"] if row else 0

        # 按协议汇总
        cursor2 = await self._conn.execute(
            """SELECT l7_proto AS protocol, SUM(bytes_sent + bytes_recv) AS bytes
               FROM flows WHERE timestamp_s >= ?
               GROUP BY l7_proto ORDER BY bytes DESC""",
            (since_ts,),
        )
        rows2 = await cursor2.fetchall()
        by_protocol = [{"protocol": r["protocol"], "bytes": r["bytes"]} for r in rows2]

        # 按分类汇总
        cursor3 = await self._conn.execute(
            """SELECT l7_category AS category, SUM(bytes_sent + bytes_recv) AS bytes
               FROM flows WHERE timestamp_s >= ? AND l7_category != ''
               GROUP BY l7_category ORDER BY bytes DESC""",
            (since_ts,),
        )
        rows3 = await cursor3.fetchall()
        by_category = [{"category": r["category"], "bytes": r["bytes"]} for r in rows3]

        return TrafficTotal(
            total_bytes=total_bytes,
            total_packets=total_packets,
            total_flows=total_flows,
            by_protocol=by_protocol,
            by_category=by_category,
            time_range=time_range,
        )

    # ── 应用服务统计 ────────────────────────────────────

    # 常见域名 → 服务名映射
    _SERVICE_MAP: dict[str, str] = {
        # Google
        "google.com": "Google", "www.google.com": "Google",
        "googleapis.com": "Google", "googleusercontent.com": "Google",
        "gstatic.com": "Google", "googleanalytics.com": "Google",
        "googlevideo.com": "YouTube", "youtube.com": "YouTube",
        "ytimg.com": "YouTube",
        # Microsoft
        "microsoft.com": "Microsoft", "live.com": "Microsoft",
        "office.com": "Microsoft", "office365.com": "Microsoft",
        "azure.com": "Azure", "windows.net": "Microsoft",
        "bing.com": "Bing",
        # 国内
        "qq.com": "QQ", "tencent.com": "腾讯",
        "weixin.qq.com": "微信", "wx.qq.com": "微信",
        "wechat.com": "微信",
        "douyin.com": "抖音", "douyincdn.com": "抖音",
        "toutiao.com": "头条",
        "pinduoduo.com": "拼多多",
        "taobao.com": "淘宝", "tmall.com": "天猫",
        "jd.com": "京东",
        "baidu.com": "百度", "bdstatic.com": "百度",
        "alipay.com": "支付宝",
        "163.com": "网易", "126.com": "网易",
        "sina.com": "新浪", "weibo.com": "微博",
        "bilibili.com": "B站", "hdslb.com": "B站",
        "zhihu.com": "知乎",
        "xiaohongshu.com": "小红书",
        "dianping.com": "大众点评",
        "meituan.com": "美团",
        "ctrip.com": "携程",
        "iqiyi.com": "爱奇艺",
        "youku.com": "优酷",
        "sohu.com": "搜狐",
        "sankuai.com": "美团",
        # AI
        "openai.com": "OpenAI/ChatGPT",
        "deepseek.com": "DeepSeek",
        "anthropic.com": "Anthropic/Claude",
        "copilot.microsoft.com": "GitHub Copilot",
        "githubcopilot.com": "GitHub Copilot",
        # 社交
        "facebook.com": "Facebook", "fbcdn.net": "Facebook",
        "instagram.com": "Instagram", "cdninstagram.com": "Instagram",
        "twitter.com": "Twitter/X", "x.com": "Twitter/X",
        "linkedin.com": "LinkedIn",
        "reddit.com": "Reddit",
        "telegram.org": "Telegram", "t.me": "Telegram",
        "whatsapp.com": "WhatsApp", "whatsapp.net": "WhatsApp",
        "discord.com": "Discord", "discordapp.com": "Discord",
        # 流媒体
        "netflix.com": "Netflix", "nflxvideo.net": "Netflix",
        "spotify.com": "Spotify",
        "twitch.tv": "Twitch",
        "hulu.com": "Hulu",
        "disneyplus.com": "Disney+",
        # 开发/Git
        "github.com": "GitHub", "githubassets.com": "GitHub",
        "gitlab.com": "GitLab",
        "stackoverflow.com": "Stack Overflow",
        "npmjs.org": "npm", "npmjs.com": "npm",
        "pypi.org": "PyPI",
        "docker.com": "Docker", "docker.io": "Docker",
        "hub.docker.com": "Docker Hub",
        # 云服务
        "aws.amazon.com": "AWS", "amazonaws.com": "AWS",
        "cloudflare.com": "Cloudflare",
        "digitalocean.com": "DigitalOcean",
        "vercel.com": "Vercel",
        "netlify.com": "Netlify",
        # 扩展服务映射
        "render.com": "Render", "fly.io": "Fly.io",
        "heroku.com": "Heroku",
        "supabase.com": "Supabase",
        "cloud.google.com": "Google Cloud",
        "oracle.com": "Oracle", "ibm.com": "IBM",
        "salesforce.com": "Salesforce",
        "fastly.com": "Fastly",
        "datadog.com": "Datadog",
        "newrelic.com": "New Relic",
        "elastic.co": "Elastic",
        "mongodb.com": "MongoDB",
        "redis.com": "Redis",
        "postgresql.org": "PostgreSQL",
        "grafana.com": "Grafana",
        "influxdata.com": "InfluxData",
        "clickhouse.com": "ClickHouse",
        "vmware.com": "VMware",
        "sap.com": "SAP",
        "akamai.com": "Akamai",
        "zoom.us": "Zoom", "zoom.com": "Zoom",
        "webex.com": "Webex",
        "adobe.com": "Adobe",
        "figma.com": "Figma",
        "canva.com": "Canva",
        "miro.com": "Miro",
        "atlassian.com": "Atlassian",
        "jira.com": "Jira",
        "trello.com": "Trello",
        "dropbox.com": "Dropbox",
        "notion.com": "Notion", "notion.so": "Notion",
        "evernote.com": "Evernote",
        "shopify.com": "Shopify",
        "stripe.com": "Stripe",
        "paypal.com": "PayPal",
        "coinbase.com": "Coinbase",
        "binance.com": "Binance",
        "ethereum.org": "Ethereum",
        "coingecko.com": "CoinGecko",
        "tailscale.com": "Tailscale",
        "openvpn.net": "OpenVPN",
        "nordvpn.com": "NordVPN",
        "protonvpn.com": "ProtonVPN",
        "signal.org": "Signal",
        "slack.com": "Slack",
        "pinterest.com": "Pinterest",
        "snapchat.com": "Snapchat",
        "soundcloud.com": "SoundCloud",
        "vimeo.com": "Vimeo",
        "hbomax.com": "HBO Max",
        "hulu.com": "Hulu",
        "disneyplus.com": "Disney+",
        "spotify.com": "Spotify",
        "twitch.tv": "Twitch",
        "netflix.com": "Netflix", "nflxvideo.net": "Netflix",
        "wix.com": "Wix",
        "wordpress.com": "WordPress",
        "jsdelivr.net": "jsDelivr",
        "cdnjs.com": "cdnjs",
        "unpkg.com": "unpkg",
        "bunnycdn.com": "BunnyCDN",
        "stackpath.com": "StackPath",
        "sentry.io": "Sentry",
        "okta.com": "Okta", "auth0.com": "Auth0",
        "zendesk.com": "Zendesk",
        "hubspot.com": "HubSpot",
        "twilio.com": "Twilio",
        "mailchimp.com": "Mailchimp",
        "ubuntu.com": "Ubuntu",
        "debian.org": "Debian",
        "kernel.org": "Linux Kernel",
        "mozilla.org": "Mozilla",
        "w3.org": "W3C", "ietf.org": "IETF",
        "whatwg.org": "WHATWG",
        "freebsd.org": "FreeBSD", "openbsd.org": "OpenBSD",
        # ── 开发框架/工具 ──
        "nodejs.org": "Node.js",
        "deno.land": "Deno", "deno.com": "Deno",
        "rubygems.org": "RubyGems",
        "crates.io": "Crates.io",
        "anaconda.com": "Anaconda",
        "flutter.dev": "Flutter",
        "swift.org": "Swift",
        "jetbrains.com": "JetBrains",
        "code.visualstudio.com": "VS Code",
        "vscode.dev": "VS Code",
        "yarnpkg.com": "Yarn", "pnpm.io": "pnpm",
        "vitejs.dev": "Vite",
        "webpack.js.org": "Webpack",
        "esbuild.github.io": "esbuild",
        "rollupjs.org": "Rollup",
        "typescriptlang.org": "TypeScript",
        "react.dev": "React", "reactjs.org": "React",
        "vuejs.org": "Vue", "nextjs.org": "Next.js",
        "nuxtjs.org": "Nuxt", "angular.io": "Angular",
        "svelte.dev": "Svelte",
        "astro.build": "Astro",
        "remix.run": "Remix",
        "gatsbyjs.com": "Gatsby",
        # ── Google 扩展 ──
        "googlemail.com": "Gmail", "gmail.com": "Gmail",
        "googledrive.com": "Google Drive",
        "docs.google.com": "Google Docs",
        "photos.google.com": "Google Photos",
        "maps.google.com": "Google Maps",
        "googleplay.com": "Google Play",
        "android.com": "Android",
        "accounts.google.com": "Google Account",
        "admin.google.com": "Google Admin",
        "analytics.google.com": "Google Analytics",
        "ads.google.com": "Google Ads",
        "developers.google.com": "Google Dev",
        "firebase.google.com": "Firebase",
        "cloud.google.com": "Google Cloud",
        "console.cloud.google.com": "GCP Console",
        "gcr.io": "Google Container Registry",
        "pkg.dev": "Google Artifact Registry",
        "googlesource.com": "Google Source",
        # ── 教育/学习 ──
        "coursera.org": "Coursera",
        "udemy.com": "Udemy", "edx.org": "edX",
        "khanacademy.org": "Khan Academy",
        "duolingo.com": "Duolingo",
        "leetcode.com": "LeetCode",
        "hackerrank.com": "HackerRank",
        "codewars.com": "CodeWars",
        "freecodecamp.org": "freeCodeCamp",
        "w3schools.com": "W3Schools",
        "geeksforgeeks.org": "GeeksforGeeks",
        # ── 社区/内容 ──
        "medium.com": "Medium",
        "dev.to": "DEV Community",
        "hashnode.com": "Hashnode",
        "substack.com": "Substack",
        "patreon.com": "Patreon",
        "buymeacoffee.com": "Buy Me a Coffee",
        "kickstarter.com": "Kickstarter",
        "change.org": "Change.org",
        # ── 效率工具 ──
        "todoist.com": "Todoist",
        "ticktick.com": "TickTick",
        "calendly.com": "Calendly",
        "clockify.me": "Clockify",
        "toggl.com": "Toggl",
        "rescuetime.com": "RescueTime",
        # ── 补充分类 ──
        "npmjs.org": "npm", "npmjs.com": "npm",
        "cloudflare.com": "Cloudflare",
        "cloudflare.net": "Cloudflare",
        "cloudflare-dns.com": "Cloudflare DNS",
        "cloudflareinsights.com": "Cloudflare Insights",
        "cloudflare-cdn.com": "Cloudflare CDN",
        "cloudflarewarp.com": "Cloudflare WARP",
        "axfr.net": "Cloudflare",
        # ── Microsoft 扩展 ──
        "microsoftonline.com": "Microsoft 365",
        "sharepoint.com": "SharePoint", "onedrive.com": "OneDrive",
        "teams.microsoft.com": "Microsoft Teams",
        "outlook.com": "Outlook", "hotmail.com": "Outlook",
        "azure.net": "Azure", "azureedge.net": "Azure CDN",
        "azurefd.net": "Azure Front Door",
        "xbox.com": "Xbox", "xboxlive.com": "Xbox Live",
        "skype.com": "Skype",
        "dynamics.com": "Microsoft Dynamics",
        "powerbi.com": "Power BI",
        "powerapps.com": "Power Apps",
        "flow.microsoft.com": "Power Automate",
        "yammer.com": "Yammer",
        # ── Apple ──
        "apple.com": "Apple", "icloud.com": "iCloud",
        "apps.apple.com": "App Store",
        "itunes.apple.com": "iTunes",
        "tv.apple.com": "Apple TV+",
        "apple-music.apple.com": "Apple Music",
        "developer.apple.com": "Apple Developer",
        "icloud-content.com": "iCloud Content",
        "icloud.com.cn": "iCloud 中国",
        "push.apple.com": "Apple Push",
        # ── 腾讯扩展 ──
        "work.weixin.qq.com": "企业微信",
        "tencent-cloud.com": "腾讯云",
        "qcloud.com": "腾讯云", "tencentcs.com": "腾讯云",
        "v.qq.com": "腾讯视频",
        "qqmusic.com": "QQ音乐", "y.qq.com": "QQ音乐",
        "game.qq.com": "腾讯游戏",
        "dnf.qq.com": "DNF",
        "lol.qq.com": "英雄联盟",
        "tenpay.com": "微信支付",
        "tencentmind.com": "腾讯广告",
        # ── 阿里扩展 ──
        "aliyun.com": "阿里云", "aliyuncs.com": "阿里云",
        "amap.com": "高德地图",
        "alicdn.com": "阿里CDN",
        "1688.com": "1688",
        "youku.com": "优酷", "tudou.com": "土豆",
        "dingtalk.com": "钉钉", "dtalk.com": "钉钉",
        "ele.me": "饿了么",
        "cainiao.com": "菜鸟物流",
        "koubei.com": "口碑",
        "alibaba-inc.com": "阿里巴巴",
        "aligames.com": "阿里游戏",
        # ── 字节跳动扩展 ──
        "bytedance.com": "字节跳动",
        "tiktok.com": "TikTok", "tiktokcdn.com": "TikTok CDN",
        "ixigua.com": "西瓜视频",
        "feishu.cn": "飞书", "larksuite.com": "Lark",
        "volcengine.com": "火山引擎", "volces.com": "火山引擎",
        "snssdk.com": "字节跳动SDK",
        "pstatp.com": "字节跳动",
        "bytedns.net": "字节DNS",
        # ── 百度扩展 ──
        "pan.baidu.com": "百度网盘",
        "baidubce.com": "百度云",
        "baiducloud.com": "百度云",
        "tieba.baidu.com": "百度贴吧",
        "baike.baidu.com": "百度百科",
        "zhidao.baidu.com": "百度知道",
        "map.baidu.com": "百度地图",
        "xueshu.baidu.com": "百度学术",
        "dueros.com": "小度",
        "hao123.com": "hao123",
        # ── 网易扩展 ──
        "music.163.com": "网易云音乐",
        "youdao.com": "有道",
        "netease.im": "网易云信",
        "lofter.com": "LOFTER",
        "kaola.com": "考拉海购",
        # ── 其他中国扩展 ──
        "kuaishou.com": "快手", "gifshow.com": "快手",
        "kwai.com": "Kwai",
        "xiaomi.com": "小米", "mi.com": "小米",
        "miui.com": "MIUI",
        "huawei.com": "华为", "hicloud.com": "华为云",
        "vmall.com": "华为商城",
        "harmonyos.com": "鸿蒙OS",
        "oppo.com": "OPPO", "vivo.com": "vivo",
        "oneplus.net": "一加",
        "meizu.com": "魅族",
        "lenovo.com": "联想",
        "zte.com.cn": "中兴",
        "360.cn": "360", "qhcdn.com": "360CDN",
        "so.com": "360搜索",
        "sogou.com": "搜狗", "sogoucdn.com": "搜狗",
        "uc.cn": "UC浏览器", "ucweb.com": "UCWeb",
        "coolapk.com": "酷安",
        # ── AI 扩展 ──
        "chatgpt.com": "ChatGPT",
        "claude.ai": "Claude",
        "huggingface.co": "HuggingFace",
        "perplexity.ai": "Perplexity",
        "mistral.ai": "Mistral AI",
        "cursor.com": "Cursor", "cursor.sh": "Cursor",
        "windsurf.com": "Windsurf",
        "codeium.com": "Codeium",
        "tabnine.com": "Tabnine",
        "cohere.com": "Cohere",
        "replicate.com": "Replicate",
        "gradio.app": "Gradio",
        "wandb.ai": "Weights & Biases",
        "neptune.ai": "Neptune.ai",
        "kaggle.com": "Kaggle",
        "databricks.com": "Databricks",
        "modal.com": "Modal",
        "together.ai": "Together AI",
        "stability.ai": "Stability AI",
        "midjourney.com": "Midjourney",
        # ── 开发工具扩展 ──
        "gitlab.com": "GitLab", "bitbucket.org": "Bitbucket",
        "pypi.org": "PyPI",
        "docker.io": "Docker",
        "hub.docker.com": "Docker Hub",
        "kubernetes.io": "Kubernetes", "k8s.io": "Kubernetes",
        "helm.sh": "Helm",
        "istio.io": "Istio", "envoyproxy.io": "Envoy",
        "terraform.io": "Terraform",
        "hashicorp.com": "HashiCorp",
        "nginx.com": "nginx", "nginx.org": "nginx",
        "apache.org": "Apache",
        "rust-lang.org": "Rust",
        "golang.org": "Go", "go.dev": "Go",
        "nodejs.org": "Node.js",
        "deno.land": "Deno",
        "stackoverflow.com": "Stack Overflow",
        "postman.com": "Postman",
        "swagger.io": "Swagger",
        "graphql.org": "GraphQL",
        "grpc.io": "gRPC",
        "jupyter.org": "Jupyter",
        "colab.research.google.com": "Google Colab",
        # ── 框架/前端 ──
        "reactjs.org": "React", "react.dev": "React",
        "vuejs.org": "Vue",
        "angular.io": "Angular",
        "svelte.dev": "Svelte",
        "nextjs.org": "Next.js",
        "nuxtjs.org": "Nuxt",
        "gatsbyjs.com": "Gatsby",
        "astro.build": "Astro",
        "remix.run": "Remix",
        "vitejs.dev": "Vite",
        "webpack.js.org": "Webpack",
        "typescriptlang.org": "TypeScript",
        "eslint.org": "ESLint",
        "prettier.io": "Prettier",
        "babeljs.io": "Babel",
        "yarnpkg.com": "Yarn",
        # ── 云服务扩展 ──
        "heroku.com": "Heroku", "herokuapp.com": "Heroku Apps",
        "render.com": "Render",
        "fly.io": "Fly.io",
        "railway.app": "Railway",
        "supabase.com": "Supabase", "supabase.co": "Supabase",
        "firebaseio.com": "Firebase",
        "cloud.google.com": "Google Cloud",
        "oracle.com": "Oracle",
        "ibm.com": "IBM",
        "salesforce.com": "Salesforce",
        "force.com": "Salesforce",
        "sap.com": "SAP",
        "vmware.com": "VMware",
        "akamai.com": "Akamai",
        "akamaihd.net": "Akamai HD",
        "akamaiedge.net": "Akamai",
        "fastly.com": "Fastly", "fastly.net": "Fastly",
        "bunnycdn.com": "BunnyCDN", "bunny.net": "BunnyCDN",
        "keycdn.com": "KeyCDN",
        # ── 监控/可观测 ──
        "datadog.com": "Datadog", "datadoghq.com": "Datadog",
        "newrelic.com": "New Relic",
        "splunk.com": "Splunk",
        "elastic.co": "Elastic",
        "elastic-cloud.com": "Elastic Cloud",
        "grafana.com": "Grafana", "grafana.net": "Grafana",
        "prometheus.io": "Prometheus",
        "sentry.io": "Sentry",
        "loggly.com": "Loggly",
        "sumologic.com": "Sumo Logic",
        # ── 数据库 ──
        "mongodb.com": "MongoDB", "mongodb.net": "MongoDB Atlas",
        "redis.com": "Redis", "redis.net": "Redis",
        "mysql.com": "MySQL",
        "postgresql.org": "PostgreSQL",
        "sqlite.org": "SQLite",
        "cockroachlabs.com": "CockroachDB",
        "timescale.com": "TimescaleDB",
        "influxdata.com": "InfluxData",
        "clickhouse.com": "ClickHouse",
        # ── 流媒体扩展 ──
        "hbomax.com": "HBO Max",
        "hulu.com": "Hulu",
        "disneyplus.com": "Disney+",
        "disneystreaming.com": "Disney+",
        "paramountplus.com": "Paramount+",
        "peacocktv.com": "Peacock",
        "soundcloud.com": "SoundCloud",
        "vimeo.com": "Vimeo",
        "dailymotion.com": "Dailymotion",
        "crunchyroll.com": "Crunchyroll",
        "tidal.com": "Tidal",
        "deezer.com": "Deezer",
        # ── 社交扩展 ──
        "signal.org": "Signal",
        "slack.com": "Slack", "slack-edge.com": "Slack",
        "pinterest.com": "Pinterest", "pinimg.com": "Pinterest",
        "snapchat.com": "Snapchat", "sc-cdn.net": "Snapchat",
        "tumblr.com": "Tumblr",
        "quora.com": "Quora",
        "flickr.com": "Flickr",
        "imgur.com": "Imgur",
        "nextdoor.com": "Nextdoor",
        # ── 企业SaaS扩展 ──
        "zoom.us": "Zoom", "zoom.com": "Zoom",
        "webex.com": "Webex",
        "goto.com": "GoToMeeting",
        "meet.google.com": "Google Meet",
        "whereby.com": "Whereby",
        "adobe.com": "Adobe", "adobe.io": "Adobe",
        "behance.net": "Behance",
        "dribbble.com": "Dribbble",
        "figma.com": "Figma",
        "canva.com": "Canva",
        "miro.com": "Miro",
        "lucidchart.com": "Lucidchart",
        "excalidraw.com": "Excalidraw",
        "atlassian.com": "Atlassian",
        "jira.com": "Jira", "jira.net": "Jira",
        "confluence.com": "Confluence",
        "trello.com": "Trello",
        "asana.com": "Asana",
        "monday.com": "Monday.com",
        "notion.com": "Notion", "notion.so": "Notion",
        "evernote.com": "Evernote",
        "dropbox.com": "Dropbox",
        "dropboxusercontent.com": "Dropbox",
        "box.com": "Box",
        "shopify.com": "Shopify", "shopifycdn.com": "Shopify CDN",
        "stripe.com": "Stripe",
        "paypal.com": "PayPal", "paypalobjects.com": "PayPal",
        "square.com": "Square",
        "braintree.com": "Braintree",
        "mailchimp.com": "Mailchimp",
        "sendgrid.com": "SendGrid",
        "twilio.com": "Twilio",
        "okta.com": "Okta", "auth0.com": "Auth0",
        "zendesk.com": "Zendesk",
        "intercom.com": "Intercom", "intercom.io": "Intercom",
        "hubspot.com": "HubSpot",
        "wix.com": "Wix",
        "squarespace.com": "Squarespace",
        "wordpress.com": "WordPress",
        # ── 加密/Web3 ──
        "coinbase.com": "Coinbase",
        "binance.com": "Binance", "binance.us": "Binance US",
        "okx.com": "OKX",
        "kraken.com": "Kraken",
        "bitfinex.com": "Bitfinex",
        "bybit.com": "Bybit",
        "huobi.com": "Huobi",
        "ethereum.org": "Ethereum",
        "etherscan.io": "Etherscan",
        "opensea.io": "OpenSea",
        "solana.com": "Solana",
        "polygon.technology": "Polygon",
        "coingecko.com": "CoinGecko",
        "coinmarketcap.com": "CoinMarketCap",
        "defillama.com": "DeFi Llama",
        # ── VPN/代理 ──
        "wireguard.com": "WireGuard",
        "tailscale.com": "Tailscale",
        "zerotier.com": "ZeroTier",
        "openvpn.net": "OpenVPN",
        "nordvpn.com": "NordVPN",
        "expressvpn.com": "ExpressVPN",
        "surfshark.com": "Surfshark",
        "protonvpn.com": "ProtonVPN",
        "proton.me": "Proton", "protonmail.com": "ProtonMail",
        # ── 教育扩展 ──
        "coursera.org": "Coursera",
        "udemy.com": "Udemy",
        "edx.org": "edX",
        "khanacademy.org": "Khan Academy",
        "duolingo.com": "Duolingo",
        "leetcode.com": "LeetCode",
        "hackerrank.com": "HackerRank",
        "codewars.com": "CodeWars",
        "freecodecamp.org": "freeCodeCamp",
        "w3schools.com": "W3Schools",
        "geeksforgeeks.org": "GeeksforGeeks",
        # ── 社区/内容 ──
        "medium.com": "Medium",
        "dev.to": "DEV Community",
        "hashnode.com": "Hashnode",
        "substack.com": "Substack",
        "patreon.com": "Patreon",
        "buymeacoffee.com": "Buy Me a Coffee",
        "kickstarter.com": "Kickstarter",
        "change.org": "Change.org",
        # ── 效率工具 ──
        "todoist.com": "Todoist",
        "ticktick.com": "TickTick",
        "calendly.com": "Calendly",
        "cal.com": "Cal.com",
        "clockify.me": "Clockify",
        "toggl.com": "Toggl",
        "rescuetime.com": "RescueTime",
        # ── 银行/金融 ──
        "cmbchina.com": "招商银行",
        "icbc.com.cn": "工商银行",
        "ccb.com": "建设银行",
        "bankofchina.com": "中国银行",
        "abchina.com": "农业银行",
        "bankcomm.com": "交通银行",
        "citicbank.com": "中信银行",
        "pingan.com": "平安",
        "eastmoney.com": "东方财富",
        "xueqiu.com": "雪球",
        "10jqka.com.cn": "同花顺",
        # ── CDN ──
        "jsdelivr.net": "jsDelivr",
        "cdnjs.com": "cdnjs",
        "unpkg.com": "unpkg",
        "cdn77.com": "CDN77",
        "stackpath.com": "StackPath",
        "incapsula.com": "Incapsula",
        "imperva.com": "Imperva",
        "edgecast.com": "EdgeCast",
        # ── Linux/基础 ──
        "freebsd.org": "FreeBSD", "openbsd.org": "OpenBSD",
        "alpinelinux.org": "Alpine",
        "archlinux.org": "Arch Linux",
        "fedoraproject.org": "Fedora",
        "centos.org": "CentOS",
        "redhat.com": "Red Hat",
        "opensuse.org": "openSUSE",
        "gnu.org": "GNU",
        "w3.org": "W3C",
        "ietf.org": "IETF",
        "whatwg.org": "WHATWG",
        # ── 银行/金融 扩展 ──
        "spdb.com.cn": "浦发银行",
        "spdb.com": "浦发银行",
        "cib.com.cn": "兴业银行",
        "cmbc.com.cn": "民生银行",
        "cebbank.com": "光大银行",
        "everbrightbank.com": "光大银行",
        "hxb.com.cn": "华夏银行",
        "bankofbeijing.com.cn": "北京银行",
        "boc.cn": "中国银行",
        "bankofshanghai.com": "上海银行",
        "bosc.cn": "上海银行",
        "psbc.com": "邮储银行",
        "psbc.cn": "邮储银行",
        "nbcb.com.cn": "宁波银行",
        "nbcb.cn": "宁波银行",
        "cncsb.com": "长沙银行",
        "bankofnanjing.com": "南京银行",
        "njncb.com": "南京银行",
        "hzbank.com.cn": "杭州银行",
        "hzbank.cn": "杭州银行",
        "bankofchengdu.com": "成都银行",
        "bocd.com.cn": "成都银行",
        "hkbchina.com": "汉口银行",
        "hccb.com.cn": "汉口银行",
        "cgbchina.com.cn": "广发银行",
        "cgbchina.com": "广发银行",
        "bank.pingan.com": "平安银行",
        "sdb.com.cn": "平安银行",
        "pab.com.cn": "平安银行",
        "chinaebi.com": "中信银行",
        "ecitic.com": "中信银行",
        "bankecitic.com": "中信银行",
        "bjbank.com.cn": "北京银行",
        "bankofdl.com": "大连银行",
        "bosc.com.cn": "上海银行",
        "srcb.com": "上海农商银行",
        "shrcb.com": "上海农商银行",
        "bewg.com.cn": "北京农商银行",
        "bjrcb.com": "北京农商银行",
        "grcb.com": "广州农商银行",
        "grcb.net": "广州农商银行",
        "szcb.com": "深圳农商银行",
        "webank.com": "微众银行",
        "webank.com": "微众银行",
        "mybank.cn": "网商银行",
        "mybank.com": "网商银行",
        "csai.com.cn": "中信证券",
        "citics.com": "中信证券",
        "gtja.com": "国泰君安",
        "htsc.com": "华泰证券",
        "htsc.com.cn": "华泰证券",
        "cicc.com": "中金公司",
        "cicc.com.cn": "中金公司",
        # ── 家电/智能家居 ──
        "midea.com": "美的", "midea.com.cn": "美的",
        "midea.net": "美的",
        "haier.com": "海尔", "haier.net": "海尔",
        "haier.com.cn": "海尔",
        "gree.com": "格力", "gree.com.cn": "格力",
        "tcl.com": "TCL", "tcl.com.cn": "TCL",
        "hisense.com": "海信", "hisense.com.cn": "海信",
        "changhong.com": "长虹", "changhong.com.cn": "长虹",
        "konka.com": "康佳", "konka.com.cn": "康佳",
        "skyworth.com": "创维", "skyworth.com.cn": "创维",
        "aux.com.cn": "奥克斯",
        "auxgroup.com": "奥克斯",
        "chunlan.com": "春兰",
        "frestec.com": "美菱",
        "meiling.com": "美菱",
        "littlefairy.com.cn": "小天鹅",
        "littleswan.com": "小天鹅",
        "robo-rock.com": "石头科技",
        "roborock.com": "石头科技",
        "dreame.com": "追觅",
        "dreame.tech": "追觅",
        "ecovacs.com": "科沃斯", "ecovacs.cn": "科沃斯",
        "deebot.com": "科沃斯/地宝",
        "xiaomi.com": "小米", "mi.com": "小米",
        "miwifi.com": "小米路由器",
        "iot.mi.com": "小米IoT",
        "home.mi.com": "小米智能家庭",
        "huanqin.com": "华为",
        "hilink.com": "华为HiLink",
        "huawei.com": "华为", "huawei.com.cn": "华为",
        "huaweidevice.com": "华为设备",
        "smartisan.com": "锤子",
        "360iot.com": "360 IoT",
        "jdcloud-iot.com": "京东IoT",
        "alink.com": "阿里IoT",
        "ali-smart.com": "阿里智能",
        # ── 家电品牌补充 ──
        "supor.com": "苏泊尔", "supor.com.cn": "苏泊尔",
        "joyoung.com": "九阳", "joyoung.com.cn": "九阳",
        "fotile.com": "方太", "fotile.com.cn": "方太",
        "vatti.com.cn": "华帝",
        "vatti.com": "华帝",
        "sacon.com.cn": "帅康",
        "sacon.com": "帅康",
        "robam.com": "老板电器",
        "robam.com.cn": "老板电器",
        "bdestar.com": "美的/布谷",
        "bugu.com": "布谷",
        "philips.com": "飞利浦",
        "philips.com.cn": "飞利浦中国",
        "dyson.com": "戴森",
        "dyson.cn": "戴森",
        "panasonic.com": "松下",
        "panasonic.cn": "松下中国",
        "siemens.com": "西门子",
        "siemens-home.com": "西门子家电",
        "bshg.com": "博世西门子",
        "bosch.com": "博世",
        "bosch-home.com": "博世家电",
        "lg.com": "LG", "lg.com.cn": "LG中国",
        "samsung.com": "三星", "samsung.com.cn": "三星中国",
        "sony.com": "索尼", "sony.com.cn": "索尼中国",
        "sharp.cn": "夏普",
        "sharp.com": "夏普",
        "hitachi.com": "日立",
        "hitachi.cn": "日立中国",
        "daikin.com": "大金", "daikin.com.cn": "大金",
        "daikin-china.com.cn": "大金中国",
        "gree.com.cn": "格力",
        "mhi.com": "三菱重工",
        "mitsubishi.com": "三菱",
        "mitsubishielectric.com": "三菱电机",
        "fujitsu.com": "富士通",
        "fujitsu-general.com": "富士通将军",
    }

    @staticmethod
    def _map_service(proto: str, host: str) -> str:
        """将 (l7_proto, dst_host) 映射为可读的服务名。"""
        # 特定基础协议直接返回（NTP、DHCP 等不走域名匹配）
        specific_protos = {"ntp", "dhcp", "mdns", "netbios", "ssdp"}
        if proto in specific_protos:
            return proto.upper()
        # 非泛型协议直接使用（如 nDPI 检测出的 YouTube/Netflix）
        if proto and proto not in ("tls", "ssl", "socks", "tcp", "unknown", "http"):
            return proto.upper()
        # 尝试域名映射
        if host:
            host_lower = host.lower()
            # 检测 IP 地址作为 host，直接返回原始值
            if host_lower.replace(".", "").isdigit():
                return host
            parts = host_lower.split(".")
            # 尝试逐级匹配
            for i in range(len(parts)):
                domain = ".".join(parts[i:])
                if domain in SQLiteStore._SERVICE_MAP:
                    return SQLiteStore._SERVICE_MAP[domain]
            # 取主域名作为服务名
            if len(parts) >= 2:
                return parts[-2].capitalize() + "." + parts[-1]
            return host
        # 回退到协议名
        return proto.upper() if proto else "UNKNOWN"

    async def query_services_stats(
        self,
        since: datetime,
        limit: int = 20,
    ) -> list[ServiceStat]:
        """查询应用服务流量统计（基于 l7_proto 和 dst_host 的智能映射）。"""
        assert self._conn is not None
        since_ts = int(since.timestamp())

        cursor = await self._conn.execute(
            """SELECT l7_proto, dst_host, l7_category,
                      SUM(bytes_sent + bytes_recv) AS bytes_total,
                      COUNT(*) AS flow_count
               FROM flows
               WHERE timestamp_s >= ?
               GROUP BY l7_proto, dst_host
               ORDER BY bytes_total DESC""",
            (since_ts,),
        )
        rows = await cursor.fetchall()

        # 聚合到服务级别
        service_map: dict[str, dict] = {}
        for r in rows:
            proto = r["l7_proto"] or "unknown"
            host = r["dst_host"] or ""
            cat = r["l7_category"] or ""
            svc = self._map_service(proto, host)
            if svc not in service_map:
                service_map[svc] = {"bytes": 0, "flows": 0, "cat": cat}
            service_map[svc]["bytes"] += r["bytes_total"]
            service_map[svc]["flows"] += r["flow_count"]
            # 使用最有意义的分类
            if not service_map[svc]["cat"] and cat:
                service_map[svc]["cat"] = cat

        total = sum(v["bytes"] for v in service_map.values()) or 1
        sorted_services = sorted(service_map.items(), key=lambda x: -x[1]["bytes"])

        return [
            ServiceStat(
                service=svc,
                bytes_total=info["bytes"],
                flow_count=info["flows"],
                percentage=round(info["bytes"] / total * 100, 2),
                category=info["cat"],
            )
            for svc, info in sorted_services[:limit]
        ]

    # ── 设备画像 ────────────────────────────────────────

    async def query_device_profiles(
        self,
        since_ts: int,
        page: int = 1,
        size: int = 20,
        sort_by: str = "bytes",
        time_range: str = "1h",
    ) -> DeviceProfileList:
        """查询设备画像列表（按 MAC 聚合，无 MAC 时回退到 IP）。"""
        assert self._conn is not None

        from app.geo.mac_vendor import lookup_vendor, vendor_alias

        order_map = {
            "bytes": "total_bytes DESC",
            "flows": "flow_count DESC",
            "last_seen": "last_seen DESC",
            "risk": "risk_score DESC",
        }
        order = order_map.get(sort_by, "total_bytes DESC")
        # 安全说明: order 来自上方硬编码白名单映射，不可被用户篡改，因此 f-string 是安全的
        # 按 MAC 地址聚合（若有），否则按 src_ip 聚合
        cursor = await self._conn.execute(
            f"""SELECT
                       CASE WHEN src_mac != '' THEN src_mac ELSE src_ip END AS device_id,
                       MAX(src_mac) AS src_mac,
                       src_ip,
                       SUM(bytes_sent) AS bytes_sent,
                       SUM(bytes_recv) AS bytes_recv,
                       SUM(packets_sent) AS packets_sent,
                       SUM(packets_recv) AS packets_recv,
                       SUM(bytes_sent + bytes_recv) AS total_bytes,
                       COUNT(*) AS flow_count,
                       MIN(timestamp_s) AS first_seen,
                       MAX(timestamp_s) AS last_seen,
                       MAX(risk_score) AS risk_score
                FROM flows
                WHERE timestamp_s >= ?
                GROUP BY device_id
                ORDER BY {order}""",
            (since_ts,),
        )
        rows = await cursor.fetchall()
        total = len(rows)
        offset = (page - 1) * size
        page_rows = rows[offset:offset + size]

        devices: list[DeviceProfile] = []
        for r in page_rows:
            mac = r["src_mac"] or ""
            vendor_name = lookup_vendor(mac) if mac else ""
            device_id = mac if mac else r["src_ip"]

            # 查询该设备访问的应用服务
            if mac:
                svc_cursor = await self._conn.execute(
                    """SELECT l7_proto, dst_host,
                               SUM(bytes_sent + bytes_recv) AS bytes,
                               COUNT(*) AS cnt
                        FROM flows
                        WHERE timestamp_s >= ? AND src_mac = ?
                        GROUP BY l7_proto, dst_host
                        ORDER BY bytes DESC LIMIT 5""",
                    (since_ts, mac),
                )
            else:
                svc_cursor = await self._conn.execute(
                    """SELECT l7_proto, dst_host,
                               SUM(bytes_sent + bytes_recv) AS bytes,
                               COUNT(*) AS cnt
                        FROM flows
                        WHERE timestamp_s >= ? AND src_ip = ?
                        GROUP BY l7_proto, dst_host
                        ORDER BY bytes DESC LIMIT 5""",
                    (since_ts, r["src_ip"]),
                )

            top_services = []
            seen_services: set[str] = set()
            for sr in await svc_cursor.fetchall():
                svc_name = self._map_service(sr["l7_proto"] or "", sr["dst_host"] or "")
                if svc_name not in seen_services:
                    seen_services.add(svc_name)
                    top_services.append({
                        "service": svc_name,
                        "bytes": sr["bytes"],
                        "count": sr["cnt"],
                    })

            devices.append(DeviceProfile(
                mac=mac,
                ip=r["src_ip"],
                vendor=vendor_alias(vendor_name),
                bytes_sent=r["bytes_sent"],
                bytes_recv=r["bytes_recv"],
                packets_sent=r["packets_sent"],
                packets_recv=r["packets_recv"],
                flow_count=r["flow_count"],
                first_seen=datetime.fromtimestamp(r["first_seen"]) if r["first_seen"] else None,
                last_seen=datetime.fromtimestamp(r["last_seen"]) if r["last_seen"] else None,
                risk_score=r["risk_score"],
                risk_events=1 if r["risk_score"] > 0 else 0,
                top_services=top_services,
            ))

        return DeviceProfileList(devices=devices, total=total, page=page, size=size)

    async def query_device_profile_detail(
        self,
        ip: str,
        since_ts: int,
        time_range: str = "1h",
    ) -> DeviceProfile | None:
        """查询指定设备的详细画像（支持 MAC 或 IP 查询）。"""
        assert self._conn is not None

        from app.geo.mac_vendor import lookup_vendor, vendor_alias

        # 判断查询条件：MAC 格式（含 : 或 -）或 IP
        is_mac_query = ":" in ip or "-" in ip
        if is_mac_query:
            where_clause = "src_mac = ? OR dst_mac = ?"
        else:
            where_clause = "src_ip = ? OR dst_ip = ?"

        # 基础统计
        cursor = await self._conn.execute(
            f"""SELECT
                       MAX(src_mac) AS src_mac,
                       COALESCE(SUM(bytes_sent), 0) AS bytes_sent,
                       COALESCE(SUM(bytes_recv), 0) AS bytes_recv,
                       COALESCE(SUM(packets_sent), 0) AS packets_sent,
                       COALESCE(SUM(packets_recv), 0) AS packets_recv,
                       COUNT(*) AS flow_count,
                       MIN(timestamp_s) AS first_seen,
                       MAX(timestamp_s) AS last_seen,
                       MAX(risk_score) AS risk_score
                FROM flows
                WHERE timestamp_s >= ? AND ({where_clause})""",
            (since_ts, ip, ip),
        )
        row = await cursor.fetchone()
        if not row or row["flow_count"] == 0:
            return None

        # 协议分布
        cursor2 = await self._conn.execute(
            f"""SELECT l7_proto, SUM(bytes_sent + bytes_recv) AS bytes, COUNT(*) AS cnt
               FROM flows WHERE timestamp_s >= ? AND ({where_clause})
               GROUP BY l7_proto ORDER BY bytes DESC LIMIT 10""",
            (since_ts, ip, ip),
        )
        top_protos = [{"protocol": r["l7_proto"], "bytes": r["bytes"], "count": r["cnt"]}
                       for r in await cursor2.fetchall()]

        # 访问域名
        cursor3 = await self._conn.execute(
            f"""SELECT dst_host AS host, SUM(bytes_sent + bytes_recv) AS bytes, COUNT(*) AS cnt
               FROM flows WHERE timestamp_s >= ? AND ({where_clause})
               AND dst_host != '' AND dst_host IS NOT NULL
               GROUP BY dst_host ORDER BY bytes DESC LIMIT 10""",
            (since_ts, ip, ip),
        )
        top_domains = [{"host": r["host"], "bytes": r["bytes"], "count": r["cnt"]}
                        for r in await cursor3.fetchall()]

        # 通信对端
        cursor4 = await self._conn.execute(
            f"""SELECT
                      CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END AS peer,
                      SUM(bytes_sent + bytes_recv) AS bytes,
                      COUNT(*) AS cnt,
                      CASE WHEN src_ip = ? THEN 'egress' ELSE 'ingress' END AS direction
               FROM flows WHERE timestamp_s >= ? AND ({where_clause}) AND src_ip != dst_ip
               GROUP BY peer ORDER BY bytes DESC LIMIT 10""",
            (ip, ip, since_ts, ip, ip),
        )
        top_peers = [PeerStat(ip=r["peer"], bytes_total=r["bytes"], flow_count=r["cnt"], direction=r["direction"])
                      for r in await cursor4.fetchall()]

        # 目标国家
        cursor5 = await self._conn.execute(
            f"""SELECT dst_country, SUM(bytes_sent + bytes_recv) AS bytes, COUNT(*) AS cnt
               FROM flows WHERE timestamp_s >= ? AND ({where_clause})
               AND dst_country != '' AND dst_country IS NOT NULL
               GROUP BY dst_country ORDER BY bytes DESC LIMIT 10""",
            (since_ts, ip, ip),
        )
        top_countries = [{"country": r["dst_country"], "bytes": r["bytes"], "count": r["cnt"]}
                          for r in await cursor5.fetchall()]

        first = datetime.fromtimestamp(row["first_seen"]) if row["first_seen"] else None
        last = datetime.fromtimestamp(row["last_seen"]) if row["last_seen"] else None
        active_secs = (last - first).total_seconds() if first and last else 0

        risk_score = row["risk_score"]
        risk_level = ""
        if risk_score >= 200:
            risk_level = "critical"
        elif risk_score >= 100:
            risk_level = "high"
        elif risk_score >= 10:
            risk_level = "medium"
        elif risk_score > 0:
            risk_level = "low"

        mac = row["src_mac"] or ""
        vendor_name = lookup_vendor(mac) if mac else ""

        # 按 MAC 查询时，从数据库获取该设备的真实 IP
        device_ip = ip
        if is_mac_query:
            ip_cursor = await self._conn.execute(
                "SELECT src_ip, COUNT(*) AS cnt FROM flows WHERE src_mac = ? AND timestamp_s >= ? GROUP BY src_ip ORDER BY cnt DESC LIMIT 1",
                (ip, since_ts),
            )
            ip_row = await ip_cursor.fetchone()
            if ip_row and ip_row["src_ip"]:
                device_ip = ip_row["src_ip"]

        return DeviceProfile(
            mac=mac,
            ip=device_ip,
            vendor=vendor_alias(vendor_name),
            bytes_sent=row["bytes_sent"],
            bytes_recv=row["bytes_recv"],
            packets_sent=row["packets_sent"],
            packets_recv=row["packets_recv"],
            flow_count=row["flow_count"],
            first_seen=first,
            last_seen=last,
            active_seconds=int(active_secs),
            top_protocols=top_protos,
            top_domains=top_domains,
            top_peers=top_peers,
            top_countries=top_countries,
            risk_score=risk_score,
            risk_events=1 if risk_score > 0 else 0,
            risk_level=risk_level,
        )
