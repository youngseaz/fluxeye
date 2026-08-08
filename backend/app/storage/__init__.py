"""存储层 — Repository 工厂。"""

from __future__ import annotations

import logging

from app.config import settings
from app.storage.base import StorageBackend
from app.utils.logger import get_logger

logger = get_logger("storage")


def create_storage() -> StorageBackend:
    """根据配置创建对应的存储后端实例。"""
    backend = settings.storage.backend

    if backend == "sqlite":
        from app.storage.sqlite_store import SQLiteStore

        logger.info("存储后端: SQLite (path=%s)", settings.storage.sqlite.path)
        return SQLiteStore(settings.storage.sqlite)

    if backend == "influxdb":
        from app.storage.influxdb_store import InfluxDBStore

        logger.info("存储后端: InfluxDB (url=%s)", settings.storage.influxdb.url)
        return InfluxDBStore(settings.storage.influxdb)

    if backend == "clickhouse":
        from app.storage.clickhouse_store import ClickHouseStore

        logger.info("存储后端: ClickHouse (host=%s)", settings.storage.clickhouse.host)
        return ClickHouseStore(settings.storage.clickhouse)

    logger.error("不支持的存储后端: %s", backend)
    msg = f"Unsupported storage backend: {backend}"
    raise ValueError(msg)
