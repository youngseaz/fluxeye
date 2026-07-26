"""安全态势感知 API — 安全事件查询、风险概览。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query

from app.models.schemas import SecurityEvent, SecurityOverview, RiskDetail
from app.storage.base import StorageBackend
from app.storage.deps import get_storage

router = APIRouter(prefix="/security", tags=["security"])


@router.get("/events", response_model=list[SecurityEvent])
async def list_security_events(
    time_range: str = Query("1h", description="时间范围: 5m/15m/1h/6h/24h"),
    min_score: int = Query(0, description="最低风险分"),
    severity: str = Query("", description="按严重级别筛选: low/medium/high/severe/critical/emergency"),
    limit: int = Query(100, le=500),
    storage: StorageBackend = Depends(get_storage),
):
    """获取安全事件列表（含风险信息的流记录）。"""
    range_map = {
        "5m": timedelta(minutes=5),
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
    }
    delta = range_map.get(time_range, timedelta(hours=1))
    since = datetime.now(timezone.utc) - delta

    events = await storage.query_security_events(
        since=since,
        min_score=min_score,
        severity=severity,
        limit=limit,
    )
    return events


@router.get("/overview", response_model=SecurityOverview)
async def security_overview(
    time_range: str = Query("1h", description="时间范围: 5m/15m/1h/6h/24h"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取安全态势概览统计。"""
    range_map = {
        "5m": timedelta(minutes=5),
        "15m": timedelta(minutes=15),
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
    }
    delta = range_map.get(time_range, timedelta(hours=1))
    since = datetime.now(timezone.utc) - delta

    return await storage.query_security_overview(since=since, time_range=time_range)
