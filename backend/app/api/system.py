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
from app.pipeline_manager import get_pipeline, set_pipeline
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
        interface=pipeline.interface if pipeline else "",
        version=settings.app.version,
    )


@router.get("/system/storage", response_model=StorageInfo)
async def get_storage_info():
    """获取磁盘存储使用情况。

    统计规则：
    - pcap_dir = 配置的 pcap 缓存目录
    - data_path = pcap_dir 的父级 data/ 目录
    - mount_point = data_path 所在的挂载点
    - disk_total/used/free = 该挂载点的分区统计
    - data_size_bytes = data_path 目录下所有文件实际总大小
    """
    pcap_dir_raw = settings.collector.pcap_output.dir
    pcap_dir = Path(pcap_dir_raw).resolve()
    # 录制目录 = 缓存目录的父级
    record_dir = pcap_dir.parent.resolve() if pcap_dir.name == "cache" else pcap_dir

    # 确定 data 目录
    data_path = pcap_dir.parent.parent if pcap_dir.name == "cache" else pcap_dir.parent
    if not data_path.exists():
        data_path = Path(pcap_dir_raw).parent.resolve()
    if not data_path.exists():
        data_path = Path.cwd()

    # 使用 data_path 确定挂载点统计（保证目录存在）
    disk = shutil.disk_usage(data_path)
    mount_point = _get_mount_point(str(data_path))

    # 计算 data 目录实际占用
    data_size = _dir_size(data_path) if data_path.exists() else 0

    # 统计 pcap 文件（缓存 + 录制）
    pcap_files = 0
    pcap_size = 0
    for d in [pcap_dir, record_dir]:
        if d.exists():
            for f in d.glob("*.pcap"):
                pcap_files += 1
                try:
                    pcap_size += f.stat().st_size
                except OSError:
                    continue

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
    """获取 pcap 缓存配置。"""
    return PcapCleanupConfig(
        enabled=settings.collector.pcap_output.enabled,
        storage_threshold_percent=settings.collector.pcap_output.storage_threshold_percent,
        exclude_categories=list(settings.collector.pcap_output.exclude_categories),
        exclude_protocols=list(settings.collector.pcap_output.exclude_protocols),
    )


@router.post("/system/pcap/config")
async def update_pcap_cleanup_config(config: PcapCleanupConfig):
    """更新 pcap 缓存配置（是否缓存数据包 + 清理阈值）。

    修改缓存开关后，若采集流水线正在运行则自动重启使其生效。
    """
    if not (10 <= config.storage_threshold_percent <= 99):
        raise HTTPException(400, "阈值必须在 10-99 之间")

    changed = False
    if settings.collector.pcap_output.enabled != config.enabled:
        settings.collector.pcap_output.enabled = config.enabled
        changed = True
        logger.info("数据包缓存已%s", "开启" if config.enabled else "关闭")

    if settings.collector.pcap_output.storage_threshold_percent != config.storage_threshold_percent:
        settings.collector.pcap_output.storage_threshold_percent = config.storage_threshold_percent
        logger.info("pcap 清理阈值已更新为 %d%%", config.storage_threshold_percent)

    # 大流量传输不保存 pcap：分类 / 协议名排除（小写去重归一化）
    new_cats = sorted({c.strip().lower() for c in (config.exclude_categories or []) if c.strip()})
    new_protos = sorted({p.strip().lower() for p in (config.exclude_protocols or []) if p.strip()})
    if list(settings.collector.pcap_output.exclude_categories) != new_cats:
        settings.collector.pcap_output.exclude_categories = new_cats
        changed = True
        logger.info("pcap 排除分类已更新: %s", new_cats)
    if list(settings.collector.pcap_output.exclude_protocols) != new_protos:
        settings.collector.pcap_output.exclude_protocols = new_protos
        changed = True
        logger.info("pcap 排除协议已更新: %s", new_protos)

    # 缓存开关变化时，重启采集流水线使其生效
    if changed:
        await _restart_pipeline_for_config()

    return {
        "message": "数据包缓存配置已更新",
        "enabled": settings.collector.pcap_output.enabled,
        "storage_threshold_percent": settings.collector.pcap_output.storage_threshold_percent,
        "exclude_categories": list(settings.collector.pcap_output.exclude_categories),
        "exclude_protocols": list(settings.collector.pcap_output.exclude_protocols),
        "success": True,
    }


async def _restart_pipeline_for_config():
    """按当前配置重建并重启采集流水线（保持当前网口）。"""
    pipeline = get_pipeline()
    if not pipeline or not pipeline.is_running:
        return
    interface = pipeline.interface
    try:
        await pipeline.stop()
    except Exception as e:
        logger.warning("停止流水线失败: %s", e)

    from app.collector.pipeline import CapturePipeline
    from app.geo.deps import get_geo_resolver

    storage = await get_storage()
    geo_resolver = get_geo_resolver()
    new_pipeline = CapturePipeline(
        storage=storage,
        interface=interface,
        dpi_lib_path=settings.collector.dpi_lib_path,
        flush_interval=settings.collector.flush_interval,
        idle_timeout=settings.collector.idle_timeout,
        pcap_output_enabled=settings.collector.pcap_output.enabled,
        pcap_output_dir=settings.collector.pcap_output.dir,
        pcap_max_file_size_mb=settings.collector.pcap_output.max_file_size_mb,
        pcap_max_file_count=settings.collector.pcap_output.max_file_count,
        pcap_exclude_categories=settings.collector.pcap_output.exclude_categories,
        pcap_exclude_protocols=settings.collector.pcap_output.exclude_protocols,
        tls_keylog_file=settings.collector.tls_keylog.filepath,
        geo_resolver=geo_resolver,
        ipfix_enabled=settings.collector.ipfix.enabled,
        ipfix_host=settings.collector.ipfix.host,
        ipfix_port=settings.collector.ipfix.port,
        ipfix_export_interval=settings.collector.ipfix.export_interval,
    )
    set_pipeline(new_pipeline)
    await new_pipeline.start()
    logger.info("已按新缓存配置重启采集流水线 (interface=%s)", interface)
