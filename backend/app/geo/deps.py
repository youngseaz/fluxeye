"""GeoIP 解析器依赖注入 — FastAPI Depends 使用。

支持启动时自动检查和后台定时更新 GeoIP 数据库。
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from app.config import settings
from app.geo.resolver import GeoIPResolver, GeoInfo
from app.utils.logger import get_logger

logger = get_logger("geo.deps")

# 全局单例
_resolver: GeoIPResolver | None = None
_update_task: asyncio.Task | None = None


def _needs_update(db_path: str, max_age_days: int = 7) -> bool:
    """检查数据库文件是否需要更新。

    文件不存在或超过 max_age_days 天未修改则返回 True。
    """
    path = Path(db_path)
    if not path.exists():
        return True
    age_days = (time.time() - path.stat().st_mtime) / 86_400
    return age_days > max_age_days


async def download_dbs() -> None:
    """后台下载 GeoIP 数据库（在线程池中执行以避免阻塞事件循环）。"""
    from scripts.download_geoip import download_all  # type: ignore[import-untyped]

    logger.info("GeoIP 数据库需要更新，后台下载中 ...")
    loop = asyncio.get_event_loop()

    def _run():
        download_all()  # 内部会打印详细日志
        return True

    await loop.run_in_executor(None, _run)
    # 无论部分失败还是全部成功，都重新加载解析器
    reload_resolver()
    logger.info("GeoIP 数据库更新完成（可能部分跳过），解析器已重新加载")


async def _auto_update_loop() -> None:
    """定时检查并更新 GeoIP 数据库。

    启动时立即检查一次，之后按 settings.geoip.update_interval_days 间隔运行。
    """
    interval = settings.geoip.update_interval_days
    if interval <= 0:
        return

    interval_seconds = interval * 86_400  # 天 → 秒

    while True:
        try:
            cfg = settings.geoip
            needs = False
            for edition_id in cfg.edition_ids:
                # 根据 edition_id 找到对应的 db_path
                if "City" in edition_id:
                    db_path = cfg.city_db
                elif "ASN" in edition_id:
                    db_path = cfg.asn_db
                elif "Country" in edition_id:
                    db_path = getattr(cfg, 'country_db', str(Path(cfg.city_db).parent / f"{edition_id}.mmdb"))
                else:
                    # 其他 edition 存到同一目录
                    db_path = str(Path(cfg.city_db).parent / f"{edition_id}.mmdb")

                if _needs_update(db_path, interval):
                    needs = True
                    break

            if needs:
                await download_dbs()
                # 下载后重新加载解析器
                reload_resolver()
            else:
                logger.debug("GeoIP 数据库无需更新")
        except Exception as e:
            logger.warning("GeoIP 自动更新检查异常: %s", e)

        await asyncio.sleep(interval_seconds)


def _build_resolver() -> GeoIPResolver:
    """根据当前配置构造 GeoIP 解析器。"""
    return GeoIPResolver(
        city_db_path=settings.geoip.city_db,
        asn_db_path=settings.geoip.asn_db,
        country_db_path=getattr(settings.geoip, 'country_db', ''),
    )


def reload_resolver() -> None:
    """重新加载 GeoIP 解析器（下载新数据库后调用）。

    先建新解析器再关旧解析器，避免管道中的旧引用突然失效。
    """
    global _resolver
    new_resolver = _build_resolver()
    if _resolver:
        _resolver.close()
    _resolver = new_resolver

    # 同步更新管道中的解析器引用（如果管道正在运行）
    from app.pipeline_manager import get_pipeline
    pipeline = get_pipeline()
    if pipeline is not None and hasattr(pipeline, 'geo_resolver'):
        pipeline.geo_resolver = new_resolver


def get_geo_resolver() -> GeoIPResolver:
    """获取全局 GeoIP 解析器单例。"""
    global _resolver
    if _resolver is None:
        _resolver = _build_resolver()
    return _resolver


def start_auto_update() -> None:
    """启动 GeoIP 数据库自动更新后台任务。

    应在应用启动时调用（lifespan 的 startup 阶段）。
    """
    global _update_task
    if _update_task is not None:
        return

    if not settings.geoip.auto_update:
        logger.info("GeoIP 自动更新已禁用 (geoip.auto_update=false)")
        return

    _update_task = asyncio.create_task(_auto_update_loop(), name="geoip-update")
    logger.info(
        "GeoIP 自动更新已启动 (间隔 %d 天)",
        settings.geoip.update_interval_days,
    )


def stop_auto_update() -> None:
    """停止 GeoIP 自动更新后台任务。

    应在应用关闭时调用（lifespan 的 shutdown 阶段）。
    """
    global _update_task
    if _update_task is not None:
        _update_task.cancel()
        _update_task = None
        logger.info("GeoIP 自动更新已停止")


def close_geo_resolver() -> None:
    """关闭 GeoIP 解析器（应用退出时调用）。"""
    global _resolver
    if _resolver:
        _resolver.close()
        _resolver = None
