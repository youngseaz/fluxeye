"""系统状态 API。"""

from __future__ import annotations

import time
import logging

from fastapi import APIRouter

from app.config import settings
from app.models.schemas import SystemStatus
from app.pipeline_manager import get_pipeline
from app.storage.deps import get_storage

logger = logging.getLogger(__name__)
_start_time = time.time()

router = APIRouter(tags=["system"])


@router.get("/system/status", response_model=SystemStatus)
async def get_system_status():
    """获取系统运行状态。"""
    storage = await get_storage()
    pipeline = get_pipeline()

    return SystemStatus(
        status="running",
        uptime_seconds=int(time.time() - _start_time),
        storage_backend=storage.__class__.__name__.replace("Store", "").lower(),
        collector_running=pipeline.is_running if pipeline else False,
        flows_cached=pipeline.flow_manager.active_count if pipeline else 0,
        version=settings.app.version,
    )
