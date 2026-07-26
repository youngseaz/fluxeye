"""采集流水线管理器 — 全局单例，避免循环导入。"""

from __future__ import annotations

from typing import Optional

from app.collector.pipeline import CapturePipeline
from app.flow.manager import FlowManager
from app.models.schemas import FlowRecord

# 全局采集流水线单例
_pipeline: Optional[CapturePipeline] = None


def set_pipeline(pipeline: CapturePipeline) -> None:
    global _pipeline
    _pipeline = pipeline


def get_pipeline() -> Optional[CapturePipeline]:
    return _pipeline


def get_flow_manager() -> Optional[FlowManager]:
    """获取当前流水线的流管理器（用于实时查询活跃流）。"""
    pipeline = get_pipeline()
    if pipeline is None:
        return None
    return pipeline.flow_manager


def get_active_flows() -> list[FlowRecord]:
    """获取当前所有活跃流（实时，不入库）。"""
    mgr = get_flow_manager()
    if mgr is None:
        return []
    return mgr.get_active_flows()
