"""流量数据 API — 概览、协议分布、Top Talkers、时序数据。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from typing import Optional

from app.models.schemas import (
    AppStat,
    Conversation,
    DomainStat,
    ProtocolDistribution,
    ProtocolStat,
    ServiceStat,
    TimePoint,
    TimeSeriesResponse,
    TopTalkersResponse,
    TrafficOverview,
    TrafficTotal,
)
from app.pipeline_manager import get_active_flows, get_pipeline
from app.storage.base import StorageBackend
from app.storage.deps import get_storage

router = APIRouter(tags=["traffic"])


@router.get("/traffic/live", response_model=list[Conversation])
async def get_live_sessions(
    l7_proto: Optional[str] = Query(None, description="按应用层协议过滤，如 http, tls, dns"),
    l4_proto: Optional[str] = Query(None, description="按传输层协议过滤: tcp, udp"),
    src_ip: Optional[str] = Query(None, description="按源 IP 过滤"),
    dst_ip: Optional[str] = Query(None, description="按目标 IP 过滤"),
    port: Optional[int] = Query(None, description="按端口过滤（匹配源或目标）"),
    country: Optional[str] = Query(None, description="按目标国家过滤，如 US, CN"),
):
    """获取当前活跃会话（内存中的实时流，不查数据库）。

    支持按协议、IP、端口、国家等条件过滤。
    """
    flows = get_active_flows()

    # 客户端过滤
    if l7_proto:
        flows = [f for f in flows if f.l7_proto.lower() == l7_proto.lower()]
    if l4_proto:
        flows = [f for f in flows if f.l4_proto.lower() == l4_proto.lower()]
    if src_ip:
        flows = [f for f in flows if src_ip in f.src_ip]
    if dst_ip:
        flows = [f for f in flows if dst_ip in f.dst_ip]
    if port:
        flows = [f for f in flows if f.src_port == port or f.dst_port == port]
    if country:
        flows = [f for f in flows if f.dst_country.upper() == country.upper()]

    return [
        Conversation(
            id=0,
            timestamp=f.timestamp,
            src_ip=f.src_ip,
            dst_ip=f.dst_ip,
            src_port=f.src_port,
            dst_port=f.dst_port,
            l4_proto=f.l4_proto,
            l7_proto=f.l7_proto,
            bytes_sent=f.bytes_sent,
            bytes_recv=f.bytes_recv,
            packets_sent=f.packets_sent,
            packets_recv=f.packets_recv,
            l7_meta=f.l7_meta,
            l7_category=f.l7_category,
            duration_ms=f.duration_ms,
            dst_host=f.dst_host,
            interface=f.interface,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
            dst_country=f.dst_country,
            dst_region=f.dst_region,
            dst_city=f.dst_city,
            dst_asn=f.dst_asn,
            dst_as_org=f.dst_as_org,
            dst_lat=f.dst_lat,
            dst_lon=f.dst_lon,
        )
        for f in flows
    ]


@router.get("/traffic/overview", response_model=TrafficOverview)
async def get_overview(
    time_range: str = Query("5m", description="时间范围，如 5m, 1h, 1d"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取实时流量概览（含活跃流数据）。"""
    db_overview = await storage.query_overview(time_range=time_range)

    # 补充活跃流数据
    from app.pipeline_manager import get_pipeline
    pipeline = get_pipeline()
    active_flows = pipeline.flow_manager.get_active_flows() if pipeline else []
    active_bytes = sum(f.bytes_sent + f.bytes_recv for f in active_flows)
    active_packets = sum(f.packets_sent + f.packets_recv for f in active_flows)

    # 将时间范围转为秒数
    unit = time_range[-1]
    value = int(time_range[:-1])
    span = value * {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 60)

    return TrafficOverview(
        total_bps=db_overview.total_bps + (active_bytes / span * 8 if span > 0 else 0),
        total_pps=db_overview.total_pps + (active_packets / span if span > 0 else 0),
        active_flows=len(active_flows) + db_overview.active_flows,
        total_connections=len(active_flows) + db_overview.total_connections,
        time_range=time_range,
    )


@router.get("/traffic/protocols", response_model=ProtocolDistribution)
async def get_protocols(
    time_range: str = Query("1h", description="时间范围"),
    top: int = Query(10, ge=1, le=50, description="返回 Top N 协议"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取协议分布。"""
    protocols = await storage.query_protocols(time_range=time_range, top=top)
    return ProtocolDistribution(time_range=time_range, protocols=protocols)


@router.get("/traffic/top-talkers", response_model=TopTalkersResponse)
async def get_top_talkers(
    top: int = Query(20, ge=1, le=100, description="返回 Top N IP"),
    time_range: str = Query("30m", description="时间范围"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取流量 Top N IP。"""
    talkers = await storage.query_top_talkers(top=top, time_range=time_range)
    return TopTalkersResponse(time_range=time_range, top=top, talkers=talkers)


@router.get("/traffic/time-series", response_model=TimeSeriesResponse)
async def get_time_series(
    interval: str = Query("10s", description="聚合间隔，如 10s, 1m, 5m"),
    time_range: str = Query("1h", description="时间范围"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取时序流量数据。

    短时间范围 (< 1h) 使用内存时序数据（高精度），
    长时间范围从数据库聚合。
    """
    from app.pipeline_manager import get_pipeline

    # 将时间范围转为秒数
    unit = time_range[-1]
    value = int(time_range[:-1])
    span = value * {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 60)

    # 短时间范围使用内存时序数据
    if span <= 3600:
        pipeline = get_pipeline()
        if pipeline:
            max_points = max(1, span // 10)  # 每 10s 一个点
            mem_data = pipeline.get_recent_time_series(max_points)
            if mem_data:
                from datetime import datetime
                data = [
                    TimePoint(
                        timestamp=datetime.fromtimestamp(p["ts"]),
                        bps=p["bps"],
                        pps=p["pps"],
                    )
                    for p in mem_data
                ]
                return TimeSeriesResponse(
                    interval=interval, time_range=time_range, data=data
                )

    # 长时间范围从数据库聚合
    data = await storage.query_time_series(interval=interval, time_range=time_range)
    return TimeSeriesResponse(interval=interval, time_range=time_range, data=data)


@router.get("/traffic/top-domains", response_model=list[DomainStat])
async def get_top_domains(
    limit: int = Query(20, ge=1, le=100, description="返回 Top N 域名"),
    time_range: str = Query("1h", description="时间范围，如 5m, 1h, 6h"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取访问频次最高的域名统计。"""
    span = _parse_time_range(time_range)
    from datetime import datetime, timezone
    since = datetime.now(timezone.utc) - span
    return await storage.query_top_domains(since=since, limit=limit)


@router.get("/traffic/app-stats", response_model=list[AppStat])
async def get_app_stats(
    limit: int = Query(20, ge=1, le=50, description="返回 Top N 应用"),
    time_range: str = Query("1h", description="时间范围，如 5m, 1h, 6h"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取应用层协议流量统计。"""
    span = _parse_time_range(time_range)
    from datetime import datetime, timezone
    since = datetime.now(timezone.utc) - span
    return await storage.query_app_stats(since=since, limit=limit)


@router.get("/traffic/totals", response_model=TrafficTotal)
async def get_traffic_totals(
    time_range: str = Query("5m", description="时间范围，如 5m, 1h, 6h"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取流量总和统计（含按协议/分类汇总）。"""
    span = _parse_time_range(time_range)
    from datetime import datetime, timezone
    since = datetime.now(timezone.utc) - span
    return await storage.query_traffic_totals(since=since, time_range=time_range)


@router.get("/traffic/services", response_model=list[ServiceStat])
async def get_services_stats(
    limit: int = Query(20, ge=1, le=50, description="返回 Top N 应用服务"),
    time_range: str = Query("1h", description="时间范围，如 5m, 1h, 6h"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取应用服务流量统计（如 YouTube、Google、微信、抖音等）。"""
    span = _parse_time_range(time_range)
    from datetime import datetime, timezone
    since = datetime.now(timezone.utc) - span
    return await storage.query_services_stats(since=since, limit=limit)


def _parse_time_range(time_range: str):
    """将时间范围字符串转为 timedelta。"""
    unit = time_range[-1]
    value = int(time_range[:-1])
    from datetime import timedelta
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return timedelta(seconds=value * multipliers.get(unit, 60))
