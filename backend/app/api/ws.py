"""WebSocket 实时推送 — 定时推送流量概览数据。"""

from __future__ import annotations

import asyncio
import json
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.collector.pipeline import CapturePipeline
from app.models.schemas import TrafficOverview
from app.pipeline_manager import get_pipeline
from app.storage.base import StorageBackend
from app.storage.deps import get_storage

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """WebSocket 实时推送端点。

    每 1 秒推送一次流量概览数据。
    数据来源: 内存中的活跃流 + 数据库已刷出的流。
    """
    await websocket.accept()

    try:
        storage: StorageBackend = await get_storage()
        while True:
            pipeline = get_pipeline()
            active_flows = pipeline.flow_manager.get_active_flows() if pipeline else []

            # 从活跃流计算实时数据
            now = time.time()
            total_bytes = 0
            total_packets = 0
            for f in active_flows:
                total_bytes += f.bytes_sent + f.bytes_recv
                total_packets += f.packets_sent + f.packets_recv

            # 加上数据库中的历史数据
            db_overview = await storage.query_overview(time_range="5s")

            overview = TrafficOverview(
                total_bps=db_overview.total_bps + (total_bytes / 5 * 8 if total_bytes > 0 else 0),
                total_pps=db_overview.total_pps + (total_packets / 5 if total_packets > 0 else 0),
                active_flows=len(active_flows) + db_overview.active_flows,
                total_connections=len(active_flows) + db_overview.total_connections,
                time_range="5s",
            )
            await websocket.send_json(overview.model_dump())
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
