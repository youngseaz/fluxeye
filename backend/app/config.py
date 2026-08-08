"""应用配置管理 — 基于 Pydantic Settings，支持环境变量覆盖。"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings


class SQLiteConfig(BaseSettings):
    path: str = "./data/fluxeye.db"
    wal: bool = True
    journal_size_limit: int = 1_048_576  # 1 MB


class InfluxDBConfig(BaseSettings):
    url: str = "http://localhost:8086"
    token: str = ""
    org: str = "fluxeye"
    bucket: str = "flow_stats"


class ClickHouseConfig(BaseSettings):
    host: str = "localhost"
    port: int = 9000
    database: str = "fluxeye"
    user: str = "default"
    password: str = ""


class StorageConfig(BaseSettings):
    backend: Literal["sqlite", "influxdb", "clickhouse"] = "sqlite"
    sqlite: SQLiteConfig = SQLiteConfig()
    influxdb: InfluxDBConfig = InfluxDBConfig()
    clickhouse: ClickHouseConfig = ClickHouseConfig()
    retention_days: int = 7  # 流记录保留天数，超过自动清理


class PcapOutputConfig(BaseSettings):
    enabled: bool = False
    dir: str = "./data/captures"
    max_file_size_mb: int = 100
    max_file_count: int = 10
    storage_threshold_percent: int = 90  # 磁盘使用率超过此值自动清理旧 pcap
    # ── 大流量传输不保存 pcap（节省磁盘）──────────────────
    # 按 nDPI 分类排除（video/streaming/download/media/music/filesharing）
    exclude_categories: list[str] = Field(
        default_factory=lambda: ["video", "streaming", "download", "media", "music", "filesharing"]
    )
    # 按协议名排除（如 P2P 下载、QUIC、FTP 数据等大流量协议）
    exclude_protocols: list[str] = Field(
        default_factory=lambda: [
            "bittorrent", "quic", "http3", "ftp_data", "nfs",
            "smbv1", "smbv23", "rtmp", "mpegts", "mpegdash",
        ]
    )


class TLSKeyLogConfig(BaseSettings):
    filepath: str = ""  # SSLKEYLOGFILE 路径，留空则从环境变量读取
    auto_reload: bool = True
    reload_interval: float = 5.0  # 增量读取间隔(秒)


class IPFIXConfig(BaseSettings):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 4739
    export_interval: float = 10.0


class CollectorConfig(BaseSettings):
    interface: str = ""
    bpf_filter: str = ""
    snap_len: int = 65535
    promisc: bool = True
    pcap_file: str = ""  # pcap 回放路径，非空时替代网卡抓包
    flush_interval: float = 5.0  # 流刷出间隔(秒)
    idle_timeout: float = 60.0  # 流空闲超时(秒)，超时后刷出到存储；越大实时会话越稳定
    dpi_lib_path: str = "libndpi_helper.so"
    pcap_output: PcapOutputConfig = PcapOutputConfig()
    tls_keylog: TLSKeyLogConfig = TLSKeyLogConfig()
    ipfix: IPFIXConfig = IPFIXConfig()


class GeoIPConfig(BaseSettings):
    account_id: str = ""
    license_key: str = ""
    edition_ids: list[str] = ["GeoLite2-City", "GeoLite2-ASN", "GeoLite2-Country"]
    city_db: str = "./data/geoip/GeoLite2-City.mmdb"
    asn_db: str = "./data/geoip/GeoLite2-ASN.mmdb"
    country_db: str = "./data/geoip/GeoLite2-Country.mmdb"
    auto_update: bool = True
    update_interval_days: int = 7

    @field_validator("account_id", mode="before")
    @classmethod
    def coerce_account_id(cls, v: object) -> str:
        if isinstance(v, (int, float)):
            return str(v)
        return str(v) if v else ""


class CorsConfig(BaseSettings):
    origins: list[str] = ["http://localhost:5173", "http://localhost:8000"]


class AppConfig(BaseSettings):
    title: str = "FluxEye API"
    version: str = "0.1.0"
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = True
    log_level: str = "info"


class Settings(BaseSettings):
    """全局配置，从 config.yaml 加载 + 环境变量覆盖。"""

    app: AppConfig = AppConfig()
    cors: CorsConfig = CorsConfig()
    storage: StorageConfig = StorageConfig()
    collector: CollectorConfig = CollectorConfig()
    geoip: GeoIPConfig = GeoIPConfig()

    class Config:
        env_prefix = "FLUXEYE_"
        env_nested_delimiter = "__"

    @classmethod
    def from_yaml(cls, path: str | Path = "config/config.yaml") -> "Settings":
        """从 YAML 文件加载配置，未指定字段使用默认值。"""
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path) as f:
            raw = yaml.safe_load(f) or {}

        return cls(**raw)


# 全局配置单例
settings = Settings.from_yaml(os.environ.get("FLUXEYE_CONFIG", "config/config.yaml"))
