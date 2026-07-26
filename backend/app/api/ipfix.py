"""IPFIX (NetFlow v10) 导出控制 API。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import settings
from app.pipeline_manager import get_pipeline
from app.utils.logger import get_logger

logger = get_logger("api.ipfix")

router = APIRouter(prefix="/export/ipfix", tags=["export"])


class IPFIXStatus(BaseModel):
    enabled: bool = False
    running: bool = False
    host: str = ""
    port: int = 0
    observation_domain_id: int = 0


class IPFIXConfigUpdate(BaseModel):
    enabled: bool
    host: str = "127.0.0.1"
    port: int = 4739


@router.get("/status", response_model=IPFIXStatus)
async def get_ipfix_status():
    """查询 IPFIX 导出状态。"""
    pipeline = get_pipeline()
    if not pipeline:
        return IPFIXStatus()
    exporter = pipeline.ipfix_exporter
    return IPFIXStatus(
        enabled=exporter is not None,
        running=exporter.is_running if exporter else False,
        host=exporter.collector_host if exporter else "",
        port=exporter.collector_port if exporter else 0,
        observation_domain_id=exporter.observation_domain_id if exporter else 0,
    )


@router.post("/start")
async def start_ipfix_export():
    """启动 IPFIX 导出。"""
    pipeline = get_pipeline()
    if not pipeline:
        raise HTTPException(503, "采集流水线未初始化")
    if pipeline.ipfix_exporter:
        if pipeline.ipfix_exporter.is_running:
            return {"message": "IPFIX 导出已在运行"}
        pipeline.ipfix_exporter.start()
        return {"message": "IPFIX 导出已启动"}
    else:
        # 动态创建导出器
        from app.export.ipfix import IPFIXExporter
        pipeline.ipfix_exporter = IPFIXExporter(
            collector_host=settings.collector.ipfix.host,
            collector_port=settings.collector.ipfix.port,
        )
        pipeline.ipfix_exporter.start()
        # 添加导出循环任务
        import asyncio
        pipeline._tasks.append(
            asyncio.create_task(pipeline._ipfix_loop(), name="ipfix")
        )
        return {"message": "IPFIX 导出已动态启动"}


@router.post("/stop")
async def stop_ipfix_export():
    """停止 IPFIX 导出。"""
    pipeline = get_pipeline()
    if not pipeline or not pipeline.ipfix_exporter:
        raise HTTPException(400, "IPFIX 导出未运行")
    pipeline.ipfix_exporter.stop()
    return {"message": "IPFIX 导出已停止"}
