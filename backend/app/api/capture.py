"""抓包控制 API — 管理采集流水线的启停与状态查询。"""

from __future__ import annotations

import asyncio
import socket
import struct
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.collector.pipeline import CapturePipeline
from app.config import settings
from app.geo.deps import get_geo_resolver
from app.models.schemas import SystemStatus
from app.pipeline_manager import get_pipeline, set_pipeline
from app.storage.deps import get_storage
from app.utils.logger import get_logger

logger = get_logger("api.capture")

router = APIRouter(prefix="/capture", tags=["capture"])


# ── 响应模型 ───────────────────────────────────────────

class CaptureStatus(BaseModel):
    """抓包状态"""
    running: bool = False
    interface: str = ""
    pcap_file: str = ""
    packets_processed: int = 0
    uptime_seconds: float = 0.0
    active_flows: int = 0
    dpi_available: bool = False
    pcap_output_enabled: bool = False


class CaptureStartRequest(BaseModel):
    """启动抓包请求"""
    interface: str = ""
    pcap_file: str = ""
    bpf_filter: str = ""
    snap_len: int = 65535
    promisc: bool = True


class InterfaceInfo(BaseModel):
    """网卡信息"""
    name: str
    ip: str = ""
    mac: str = ""
    is_loopback: bool = False
    is_up: bool = False


# ── 工具函数 ───────────────────────────────────────────

def list_interfaces() -> list[InterfaceInfo]:
    """列出系统可用网卡。"""
    from app.collector.capture import PacketCapture
    try:
        import pcap
        result: list[InterfaceInfo] = []
        for name in pcap.findalldevs():
            info = InterfaceInfo(name=name)
            try:
                # 尝试获取 IP
                import socket as _socket
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
                s.connect((name, 80))
                info.ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass
            info.is_loopback = "lo" in name.lower()
            result.append(info)
        return result
    except ImportError:
        # 无 pcap 库 -> 从 /sys/class/net 读取
        import os
        result: list[InterfaceInfo] = []
        net_dir = "/sys/class/net"
        if os.path.isdir(net_dir):
            for name in sorted(os.listdir(net_dir)):
                info = InterfaceInfo(name=name)
                info.is_loopback = "lo" in name.lower()
                try:
                    oper = open(f"{net_dir}/{name}/operstate").read().strip()
                    info.is_up = oper == "up"
                except Exception:
                    pass
                result.append(info)
        return result


# ── 端点 ───────────────────────────────────────────────

@router.get("/status", response_model=CaptureStatus)
async def get_capture_status():
    """获取当前抓包状态。"""
    pipeline = get_pipeline()
    if not pipeline:
        return CaptureStatus()

    return CaptureStatus(
        running=pipeline.is_running,
        interface=pipeline.interface,
        pcap_file=pipeline.pcap_file,
        packets_processed=pipeline.packets_processed,
        uptime_seconds=pipeline.uptime_seconds,
        active_flows=pipeline.flow_manager.active_count,
        dpi_available=pipeline.dpi.is_available if pipeline.dpi else False,
        pcap_output_enabled=pipeline.cache_writer is not None,
    )


@router.get("/interfaces", response_model=list[InterfaceInfo])
async def get_interfaces():
    """列出系统可用网卡。"""
    return list_interfaces()


@router.post("/start")
async def start_capture(req: CaptureStartRequest):
    """启动抓包。

    不指定 interface 时使用配置中的默认值。
    """
    pipeline = get_pipeline()
    if not pipeline:
        raise HTTPException(503, "采集流水线未初始化")

    if pipeline.is_running:
        # 如果已在运行且 interface 相同，忽略
        if pipeline.interface == req.interface or (not req.interface and pipeline.interface):
            return {"message": "抓包已在运行", "interface": pipeline.interface}
        # 否则先停止
        await pipeline.stop()

    interface = req.interface or settings.collector.interface
    if not interface and not req.pcap_file:
        raise HTTPException(400, "请指定网卡接口或 pcap 文件路径")

    # 重建流水线
    storage = await get_storage()
    geo_resolver = get_geo_resolver()
    new_pipeline = CapturePipeline(
        storage=storage,
        interface=interface,
        pcap_file=req.pcap_file or settings.collector.pcap_file,
        dpi_lib_path=settings.collector.dpi_lib_path,
        flush_interval=settings.collector.flush_interval,
        pcap_output_enabled=settings.collector.pcap_output.enabled,
        pcap_output_dir=settings.collector.pcap_output.dir,
        pcap_max_file_size_mb=settings.collector.pcap_output.max_file_size_mb,
        pcap_max_file_count=settings.collector.pcap_output.max_file_count,
        tls_keylog_file=settings.collector.tls_keylog.filepath,
        geo_resolver=geo_resolver,
    )
    set_pipeline(new_pipeline)
    await new_pipeline.start()

    logger.info("抓包已启动: interface=%s pcap=%s", interface, req.pcap_file)
    return {
        "message": "抓包已启动",
        "interface": interface,
        "pcap_file": req.pcap_file or settings.collector.pcap_file,
    }


@router.post("/stop")
async def stop_capture():
    """停止抓包。"""
    pipeline = get_pipeline()
    if not pipeline or not pipeline.is_running:
        return {"message": "抓包未运行"}

    await pipeline.stop()
    logger.info("抓包已停止")
    return {"message": "抓包已停止", "packets_processed": pipeline.packets_processed}


# ── PCAP 录制控制 ───────────────────────────────────────

class PcapRecordingStartRequest(BaseModel):
    interface: str = ""
    bpf_filter: str = ""


class PcapRecordingResponse(BaseModel):
    recording: bool
    message: str = ""
    bpf_filter: str = ""
    interface: str = ""


@router.post("/recording/start", response_model=PcapRecordingResponse)
async def start_pcap_recording(req: PcapRecordingStartRequest = PcapRecordingStartRequest()):
    """开始录制 PCAP 文件。

    可指定网卡接口和 BPF 过滤。
    如果指定的接口与当前抓包接口不同，自动切换流水线。
    """
    pipeline = get_pipeline()
    if not pipeline:
        raise HTTPException(503, "采集流水线未初始化")

    # 如果指定了不同的接口，先切换流水线
    switch_interface = req.interface or pipeline.interface
    if switch_interface and pipeline.interface != switch_interface:
        logger.info("切换抓包接口: %s → %s", pipeline.interface, switch_interface)
        storage = await get_storage()
        geo_resolver = get_geo_resolver()
        await pipeline.stop()
        new_pipeline = CapturePipeline(
            storage=storage,
            interface=switch_interface,
            dpi_lib_path=settings.collector.dpi_lib_path,
            flush_interval=settings.collector.flush_interval,
            tls_keylog_file=settings.collector.tls_keylog.filepath,
            geo_resolver=geo_resolver,
        )
        set_pipeline(new_pipeline)
        await new_pipeline.start()
        pipeline = new_pipeline

    ok = pipeline.start_pcap_recording(
        output_dir=str(_get_capture_dir()),
        max_file_size_mb=settings.collector.pcap_output.max_file_size_mb,
        max_file_count=settings.collector.pcap_output.max_file_count,
        bpf_filter=req.bpf_filter,
    )
    if ok:
        return PcapRecordingResponse(
            recording=True,
            message="PCAP 录制已开启",
            bpf_filter=req.bpf_filter,
            interface=pipeline.interface,
        )
    return PcapRecordingResponse(
        recording=False,
        message="开启 PCAP 录制失败",
    )


@router.post("/recording/stop", response_model=PcapRecordingResponse)
async def stop_pcap_recording():
    """停止录制 PCAP 文件。"""
    pipeline = get_pipeline()
    if not pipeline:
        raise HTTPException(503, "采集流水线未初始化")

    ok = pipeline.stop_pcap_recording()
    if ok:
        return PcapRecordingResponse(
            recording=False,
            message="PCAP 录制已关闭",
        )
    return PcapRecordingResponse(
        recording=False,
        message="关闭 PCAP 录制失败",
    )


@router.get("/recording/status", response_model=PcapRecordingResponse)
async def get_pcap_recording_status():
    """查询 PCAP 录制状态。"""
    pipeline = get_pipeline()
    if not pipeline:
        return PcapRecordingResponse(recording=False, message="流水线未初始化")
    return PcapRecordingResponse(
        recording=pipeline.pcap_recording,
        message="录制中" if pipeline.pcap_recording else "未录制",
        bpf_filter=getattr(pipeline, "_pcap_bpf_filter", ""),
        interface=pipeline.interface,
    )


# ── PCAP 文件下载 ───────────────────────────────────────

class PcapFileInfo(BaseModel):
    """PCAP 文件信息"""
    name: str
    size_bytes: int
    modified: str


def _get_capture_dir() -> Path:
    """获取录制 pcap 的存储目录（与缓存目录分开）。"""
    cache_dir = Path(settings.collector.pcap_output.dir)
    return cache_dir.parent  # ./data/captures/


@router.get("/pcap-files", response_model=list[PcapFileInfo])
async def list_pcap_files():
    """列出可下载的 PCAP 文件。"""
    pcap_dir = _get_capture_dir()
    if not pcap_dir.exists():
        return []

    from datetime import datetime

    files: list[PcapFileInfo] = []
    for f in sorted(pcap_dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime, reverse=True):
        st = f.stat()
        files.append(PcapFileInfo(
            name=f.name,
            size_bytes=st.st_size,
            modified=datetime.fromtimestamp(st.st_mtime).isoformat(),
        ))
    return files


@router.get("/pcap-files/{filename:path}")
async def download_pcap(filename: str):
    """下载指定的 PCAP 文件。"""
    pcap_dir = _get_capture_dir()
    file_path = pcap_dir / filename

    # 安全校验：防止路径穿越
    try:
        file_path = file_path.resolve()
        pcap_dir_resolved = pcap_dir.resolve()
        if not str(file_path).startswith(str(pcap_dir_resolved)):
            raise HTTPException(403, "非法文件路径")
    except (ValueError, OSError):
        raise HTTPException(400, "无效文件名")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, "文件不存在")

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="application/vnd.tcpdump.pcap",
    )


@router.delete("/pcap-files/{filename:path}")
async def delete_pcap(filename: str):
    """删除指定的 PCAP 文件。"""
    pcap_dir = _get_capture_dir()
    file_path = pcap_dir / filename

    # 安全校验
    try:
        file_path = file_path.resolve()
        pcap_dir_resolved = pcap_dir.resolve()
        if not str(file_path).startswith(str(pcap_dir_resolved)):
            raise HTTPException(403, "非法文件路径")
    except (ValueError, OSError):
        raise HTTPException(400, "无效文件名")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, "文件不存在")

    try:
        file_path.unlink()
        logger.info("已删除 PCAP 文件: %s", filename)
        return {"message": f"已删除 {filename}"}
    except OSError as e:
        raise HTTPException(500, f"删除失败: {e}")
