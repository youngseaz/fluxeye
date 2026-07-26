"""流详情 API — 会话列表、单流查询。"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.models.schemas import Conversation, Page
from app.storage.base import StorageBackend
from app.storage.deps import get_storage

router = APIRouter(tags=["flows"])


@router.get("/traffic/conversations", response_model=Page)
async def get_conversations(
    page: int = Query(1, ge=1, description="页码"),
    size: int = Query(20, ge=1, le=100, description="每页条数"),
    l7_proto: Optional[str] = Query(None, description="按应用层协议过滤"),
    src_ip: Optional[str] = Query(None, description="按源 IP 过滤"),
    dst_ip: Optional[str] = Query(None, description="按目标 IP 过滤"),
    time_start: Optional[datetime] = Query(None, description="起始时间 (ISO8601)"),
    time_end: Optional[datetime] = Query(None, description="结束时间 (ISO8601)"),
    storage: StorageBackend = Depends(get_storage),
):
    """分页查询会话列表。"""
    return await storage.query_conversations(
        page=page,
        size=size,
        l7_proto=l7_proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        time_start=time_start,
        time_end=time_end,
    )


@router.get("/traffic/flows/{flow_id}", response_model=Optional[Conversation])
async def get_flow_detail(
    flow_id: int,
    storage: StorageBackend = Depends(get_storage),
):
    """查询单条流记录详情。"""
    record = await storage.query_flow_by_id(flow_id)
    if record is None:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "Flow not found"})
    return Conversation(
        id=flow_id,
        timestamp=record.timestamp,
        src_ip=record.src_ip,
        dst_ip=record.dst_ip,
        src_port=record.src_port,
        dst_port=record.dst_port,
        l4_proto=record.l4_proto,
        l7_proto=record.l7_proto,
        bytes_sent=record.bytes_sent,
        bytes_recv=record.bytes_recv,
        packets_sent=record.packets_sent,
        packets_recv=record.packets_recv,
        l7_meta=record.l7_meta,
        l7_category=record.l7_category,
        duration_ms=record.duration_ms,
        dst_host=record.dst_host,
        interface=record.interface,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        dst_country=record.dst_country,
        dst_region=record.dst_region,
        dst_city=record.dst_city,
        dst_asn=record.dst_asn,
        dst_as_org=record.dst_as_org,
        dst_lat=record.dst_lat,
        dst_lon=record.dst_lon,
    )
