"""Pydantic 数据模型定义 — API 请求/响应结构。"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ── 流记录 ──────────────────────────────────────────────

class FlowRecord(BaseModel):
    """单条 DPI 流记录。"""
    timestamp: datetime
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    l4_proto: str = Field(pattern="^(tcp|udp|icmp|sctp|unknown)$")
    l7_proto: str = "unknown"
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    l7_meta: str = ""
    l7_category: str = ""
    duration_ms: int = 0
    # 抓包网卡
    interface: str = ""
    # 首次与最后活动时间
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    # 目标主机/域名
    dst_host: str = ""
    # GeoIP 字段
    dst_country: str = ""
    dst_region: str = ""
    dst_city: str = ""
    dst_asn: int = 0
    dst_as_org: str = ""
    dst_lat: float = 0.0
    dst_lon: float = 0.0
    # PCAP 文件（用于回看报文）
    pcap_file: str = ""
    # 安全风险
    risks: list[dict] = Field(default_factory=list)
    risk_score: int = 0


# ── 概览 ────────────────────────────────────────────────

class TrafficOverview(BaseModel):
    """实时流量概览。"""
    total_bps: float = 0
    total_pps: float = 0
    active_flows: int = 0
    total_connections: int = 0
    time_range: str = "5m"


# ── 协议分布 ────────────────────────────────────────────

class ProtocolStat(BaseModel):
    """单条协议统计数据。"""
    l7_proto: str
    bytes_total: int
    flow_count: int
    percentage: float = 0.0


class ProtocolDistribution(BaseModel):
    """协议分布响应。"""
    time_range: str
    protocols: list[ProtocolStat]


# ── Top Talkers ─────────────────────────────────────────

class Talker(BaseModel):
    """单条 Top Talker 数据。"""
    ip: str
    bytes_total: int
    direction: str = Field(pattern="^(ingress|egress)$")


class TopTalkersResponse(BaseModel):
    """Top Talkers 响应。"""
    time_range: str
    top: int
    talkers: list[Talker]


# ── 时序数据 ────────────────────────────────────────────

class TimePoint(BaseModel):
    """时序数据点。"""
    timestamp: datetime
    bps: float = 0
    pps: float = 0


class TimeSeriesResponse(BaseModel):
    """时序数据响应。"""
    interval: str
    time_range: str
    data: list[TimePoint]


# ── 安全态势 ────────────────────────────────────────────

class RiskDetail(BaseModel):
    """单条风险详情。"""
    id: int
    name: str
    severity: int
    severity_name: str
    info: str = ""


class SecurityEvent(BaseModel):
    """安全事件 — 关联的流记录 + 风险信息。"""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    l4_proto: str
    l7_proto: str
    risks: list[RiskDetail]
    risk_score: int
    risk_level: str = ""  # 最高风险级别名称
    bytes_total: int = 0
    packets_total: int = 0
    interface: str = ""
    dst_host: str = ""
    dst_country: str = ""
    dst_city: str = ""


class SecurityOverview(BaseModel):
    """安全态势概览。"""
    total_events: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    top_risks: list[dict] = Field(default_factory=list)  # [{name, count}]
    by_severity: list[dict] = Field(default_factory=list)  # [{severity, count}]
    time_range: str = "1h"


# ── 域名统计 ────────────────────────────────────────────

class DomainStat(BaseModel):
    """域名统计数据。"""
    host: str
    bytes_total: int
    flow_count: int
    percentage: float = 0.0


# ── 应用统计 ────────────────────────────────────────────

class AppStat(BaseModel):
    """应用层协议统计数据。"""
    protocol: str
    bytes_total: int
    flow_count: int
    percentage: float = 0.0


# ── 流量总和统计 ────────────────────────────────────────

# ── 应用服务统计 ───────────────────────────────────────

class ServiceStat(BaseModel):
    """应用服务（YouTube/Google/微信等）流量统计。"""
    service: str
    bytes_total: int
    flow_count: int
    percentage: float = 0.0
    category: str = ""  # 协议分类 (video/streaming/web/chat 等)


class TrafficTotal(BaseModel):
    """流量总和统计。"""
    total_bytes: int
    total_packets: int
    total_flows: int
    by_protocol: list[dict] = Field(default_factory=list)
    by_category: list[dict] = Field(default_factory=list)
    time_range: str = "5m"


# ── 设备画像 ────────────────────────────────────────────

class PeerStat(BaseModel):
    """通信对端统计。"""
    ip: str
    bytes_total: int
    flow_count: int
    direction: str = ""


class DeviceProfile(BaseModel):
    """单台设备的流量画像。"""
    mac: str = ""
    ip: str = ""
    vendor: str = ""
    hostname: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    flow_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    active_seconds: int = 0
    top_protocols: list[dict] = Field(default_factory=list)
    top_services: list[dict] = Field(default_factory=list)
    top_domains: list[dict] = Field(default_factory=list)
    top_peers: list[PeerStat] = Field(default_factory=list)
    top_countries: list[dict] = Field(default_factory=list)
    risk_score: int = 0
    risk_events: int = 0
    risk_level: str = ""


class DeviceProfileList(BaseModel):
    """设备画像列表。"""
    devices: list[DeviceProfile]
    total: int = 0
    page: int = 1
    size: int = 20


# ── 会话列表 ────────────────────────────────────────────

class Conversation(BaseModel):
    """单条会话记录。"""
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    l4_proto: str
    l7_proto: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int = 0
    packets_recv: int = 0
    l7_meta: str = ""
    l7_category: str = ""
    duration_ms: int
    # 抓包网卡
    interface: str = ""
    # 首次与最后活动时间
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    # 目标主机/域名
    dst_host: str = ""
    # GeoIP 字段
    dst_country: str = ""
    dst_region: str = ""
    dst_city: str = ""
    dst_asn: int = 0
    dst_as_org: str = ""
    dst_lat: float = 0.0
    dst_lon: float = 0.0

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_recv


class Page(BaseModel):
    """分页响应。"""
    items: list
    total: int
    page: int
    size: int
    pages: int


# ── 系统状态 ────────────────────────────────────────────

class SystemStatus(BaseModel):
    """系统运行状态。"""
    status: str = "running"
    uptime_seconds: int = 0
    storage_backend: str = "sqlite"
    collector_running: bool = False
    flows_cached: int = 0
    version: str = "0.1.0"


# ── 存储状态 ──────────────────────────────────────────

class StorageInfo(BaseModel):
    """存储使用情况。"""
    mount_point: str = ""           # 数据所在挂载点路径
    data_path: str = ""             # 数据目录路径
    data_size_bytes: int = 0        # 数据目录实际占用大小
    disk_total: int = 0             # 挂载点总容量
    disk_used: int = 0              # 挂载点已用
    disk_free: int = 0              # 挂载点剩余
    disk_usage_percent: float = 0.0 # 挂载点使用率
    pcap_dir: str = ""              # pcap 子目录
    pcap_files: int = 0             # pcap 文件数
    pcap_size_bytes: int = 0        # pcap 文件总大小
    pcap_storage_threshold: int = 90


class PcapCleanupConfig(BaseModel):
    """pcap 老化清理配置。"""
    storage_threshold_percent: int = 90
