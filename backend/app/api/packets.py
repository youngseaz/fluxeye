"""PCAP 报文提取与查看 API。"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.collector.pcap_extract import extract_flow_packets
from app.storage.base import StorageBackend
from app.storage.deps import get_storage
from app.utils.logger import get_logger

logger = get_logger("api.packets")

router = APIRouter(prefix="/traffic", tags=["packets"])


class PacketInfo(BaseModel):
    timestamp: str
    raw_hex: str
    length: int
    summary: str


class PacketsResponse(BaseModel):
    flow_id: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    l4_proto: str
    packets: list[PacketInfo]
    total: int
    pcap_file: str


@router.get("/flows/{flow_id}/packets", response_model=PacketsResponse)
async def get_flow_packets(
    flow_id: int,
    max_packets: int = Query(50, ge=1, le=200, description="最多返回的包数"),
    storage=Depends(get_storage),
):
    """获取指定流记录的原始报文（从 pcap 文件中提取）。"""
    # 先查询流记录，获取 5-tuple + pcap_file
    flow = await storage.query_flow_by_id(flow_id)
    if not flow:
        raise HTTPException(404, "流记录不存在")

    pcap_file = getattr(flow, "pcap_file", "") or ""
    if not pcap_file or not Path(pcap_file).exists():
        raise HTTPException(404, "pcap 文件不存在或已被清理")

    packets = extract_flow_packets(
        pcap_path=pcap_file,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        l4_proto=flow.l4_proto,
        max_packets=max_packets,
    )

    return PacketsResponse(
        flow_id=flow_id,
        src_ip=flow.src_ip,
        dst_ip=flow.dst_ip,
        src_port=flow.src_port,
        dst_port=flow.dst_port,
        l4_proto=flow.l4_proto,
        packets=[PacketInfo(
            timestamp=p["timestamp"],
            raw_hex=p["raw_hex"],
            length=p["length"],
            summary=p["summary"],
        ) for p in packets],
        total=len(packets),
        pcap_file=pcap_file,
    )


@router.get("/pcap-files/{filename}/info")
async def get_pcap_file_info(filename: str):
    """获取 pcap 文件的基本信息。"""
    from app.config import settings

    pcap_dir = Path(settings.collector.pcap_output.dir)
    file_path = pcap_dir / filename

    if not file_path.exists():
        raise HTTPException(404, "文件不存在")

    st = file_path.stat()
    return {
        "filename": filename,
        "size_bytes": st.st_size,
        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
    }
