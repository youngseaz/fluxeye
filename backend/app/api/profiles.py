"""设备流量画像 API — 按 IP 聚合分析用户/设备行为特征。"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.models.schemas import DeviceProfile, DeviceProfileList, PeerStat
from app.storage.base import StorageBackend
from app.storage.deps import get_storage

router = APIRouter(prefix="/traffic", tags=["profiles"])


@router.get("/profiles", response_model=DeviceProfileList)
async def list_device_profiles(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    sort_by: str = Query("bytes", pattern="^(bytes|flows|last_seen|risk)$"),
    time_range: str = Query("1h", description="时间范围: 5m/15m/1h/6h/24h"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取所有设备（IP）的流量画像列表。"""
    span_map = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400}
    span = span_map.get(time_range, 3600)
    since = datetime.now(timezone.utc).timestamp() - span

    return await storage.query_device_profiles(
        since_ts=int(since),
        page=page,
        size=size,
        sort_by=sort_by,
        time_range=time_range,
    )


@router.get("/profiles/{ip}", response_model=Optional[DeviceProfile])
async def get_device_profile(
    ip: str,
    time_range: str = Query("1h", description="时间范围: 5m/15m/1h/6h/24h"),
    storage: StorageBackend = Depends(get_storage),
):
    """获取指定设备的详细流量画像。"""
    span_map = {"5m": 300, "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400}
    span = span_map.get(time_range, 3600)
    since = datetime.now(timezone.utc).timestamp() - span

    return await storage.query_device_profile_detail(
        ip=ip,
        since_ts=int(since),
        time_range=time_range,
    )
