"""存储后端依赖注入。"""

from __future__ import annotations

from app.storage import create_storage
from app.storage.base import StorageBackend
from app.utils.logger import get_logger

logger = get_logger("storage.deps")

# 全局存储单例
_storage: StorageBackend | None = None


async def get_storage() -> StorageBackend:
    """FastAPI 依赖项：获取全局存储后端实例。"""
    global _storage
    if _storage is None:
        _storage = create_storage()
        logger.info("正在初始化存储后端...")
        await _storage.initialize()
        logger.info("存储后端就绪")
    return _storage


async def close_storage() -> None:
    """关闭存储后端连接。"""
    global _storage
    if _storage:
        logger.info("正在关闭存储后端...")
        await _storage.close()
        _storage = None
        logger.info("存储后端已关闭")
