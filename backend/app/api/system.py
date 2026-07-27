"""系统状态 API。"""

from __future__ import annotations

import os
import shutil
import time
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException

from app.config import settings
from app.models.schemas import SystemStatus, StorageInfo, PcapCleanupConfig
from app.pipeline_manager import get_pipeline
from app.storage.deps import get_storage

logger = logging.getLogger(__name__)
_start_time = time.time()

router = APIRouter(tags=["system"])


def _get_mount_point(path: str) -> str:
    """获取路径所在挂载点。"""
    path = os.path.realpath(path)
    stat = os.stat(path)
    dev = stat.st_dev
    while True:
        parent = os.path.dirname(path)
        if parent == path:
            return path
        parent_stat = os.stat(parent)
        if parent_stat.st_dev != dev:
            return path
        path = parent


def _dir_size(path: Path) -> int:
    """递归计算目录下所有文件总大小。"""
    total = 0
    for f in path.rglob("*"):
        if f.is_file():
            try:
                total += f.stat().st_size
            except OSError:
                continue
    return total


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


@router.get("/system/storage", response_model=StorageInfo)
async def get_storage_info():
    """获取磁盘存储使用情况。

    统计规则：
    - pcap_dir = 配置的 pcap 输出目录
    - data_path = pcap_dir 的父级 data/ 目录（或 pcap_dir 本身）
    - mount_point = data_path 所在的挂载点
    - disk_total/used/free = 该挂载点的分区统计
    - data_size_bytes = data_path 目录下所有文件实际总大小
    """
    pcap_dir_raw = settings.collector.pcap_output.dir
    pcap_dir = Path(pcap_dir_raw).resolve()

    # 确定 data 目录（pcap_dir 的父级，保证存在）
    data_path = pcap_dir.parent if pcap_dir.name == "captures" else pcap_dir
    if not data_path.exists():
        # 回退到 project 根目录下的 data/
        data_path = Path(pcap_dir_raw).parent.resolve()
    if not data_path.exists():
        data_path = Path.cwd()

    # 使用 data_path 确定挂载点统计（保证目录存在）
    disk = shutil.disk_usage(data_path)
    mount_point = _get_mount_point(str(data_path))

    # 计算 data 目录实际占用
    data_size = _dir_size(data_path) if data_path.exists() else 0

    # 统计 pcap 文件
    pcap_files = 0
    pcap_size = 0
    if pcap_dir.exists():
        for f in pcap_dir.glob("*.pcap"):
            pcap_files += 1
            pcap_size += f.stat().st_size

    return StorageInfo(
        mount_point=mount_point,
        data_path=str(data_path),
        data_size_bytes=data_size,
        disk_total=disk.total,
        disk_used=disk.used,
        disk_free=disk.free,
        disk_usage_percent=round(disk.used / disk.total * 100, 1),
        pcap_dir=str(pcap_dir),
        pcap_files=pcap_files,
        pcap_size_bytes=pcap_size,
        pcap_storage_threshold=settings.collector.pcap_output.storage_threshold_percent,
    )


@router.post("/system/pcap/cleanup")
async def trigger_pcap_cleanup():
    """手动触发 pcap 清理：删除最旧的文件直到磁盘使用率低于阈值。"""
    pcap_dir = Path(settings.collector.pcap_output.dir)
    if not pcap_dir.exists():
        raise HTTPException(404, "pcap 目录不存在")

    threshold = settings.collector.pcap_output.storage_threshold_percent
    disk = shutil.disk_usage(pcap_dir)
    usage = disk.used / disk.total * 100

    if usage < threshold:
        return {"message": f"磁盘使用率 {usage:.1f}% 低于阈值 {threshold}%，无需清理", "deleted": 0}

    files = sorted(pcap_dir.glob("*.pcap"), key=lambda f: f.stat().st_mtime)
    deleted = 0
    for f in files:
        if usage < threshold:
            break
        try:
            f.unlink()
            deleted += 1
            disk = shutil.disk_usage(pcap_dir)
            usage = disk.used / disk.total * 100
        except OSError:
            continue

    return {
        "message": f"已清理 {deleted} 个 pcap 文件，当前磁盘使用率 {usage:.1f}%",
        "deleted": deleted,
        "disk_usage_percent": round(usage, 1),
    }


@router.get("/system/pcap/config", response_model=PcapCleanupConfig)
async def get_pcap_cleanup_config():
    """获取 pcap 清理配置。"""
    return PcapCleanupConfig(
        storage_threshold_percent=settings.collector.pcap_output.storage_threshold_percent,
    )


@router.post("/system/pcap/config")
async def update_pcap_cleanup_config(config: PcapCleanupConfig):
    """更新 pcap 清理配置。"""
    if not (10 <= config.storage_threshold_percent <= 99):
        raise HTTPException(400, "阈值必须在 10-99 之间")
    settings.collector.pcap_output.storage_threshold_percent = config.storage_threshold_percent
    logger.info("pcap 清理阈值已更新为 %d%%", config.storage_threshold_percent)
    return {"message": f"pcap 清理阈值已更新为 {config.storage_threshold_percent}%", "success": True}
