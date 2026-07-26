"""FluxEye 后端主入口 — Uvicorn + FastAPI 应用。"""

from __future__ import annotations

from pathlib import Path

import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, JSONResponse

from app.api.router import api_router
from app.collector.pipeline import CapturePipeline
from app.config import settings
from app.geo.deps import (
    close_geo_resolver,
    get_geo_resolver,
    start_auto_update,
    stop_auto_update,
)
from app.pipeline_manager import get_pipeline, set_pipeline
from app.storage.base import StorageBackend
from app.storage.deps import close_storage, get_storage
from app.utils.logger import get_logger, init_logging

# 初始化全局日志（在导入其他模块之前）
logger = init_logging(
    level=settings.app.log_level.upper(),
    log_file="./logs/fluxeye.log",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理。"""

    # 启动时：初始化存储后端 + GeoIP 解析器
    storage = await get_storage()
    geo_resolver = get_geo_resolver()
    if geo_resolver.is_available:
        logger.info("GeoIP 解析器已就绪")
    else:
        logger.info("GeoIP 解析器未就绪 (数据库文件缺失)")

    # 启动 GeoIP 数据库自动更新
    start_auto_update()

    # 启动采集流水线
    pipeline = CapturePipeline(
        storage=storage,
        interface=settings.collector.interface,
        pcap_file=settings.collector.pcap_file,
        dpi_lib_path=settings.collector.dpi_lib_path,
        flush_interval=settings.collector.flush_interval,
        pcap_output_enabled=settings.collector.pcap_output.enabled,
        pcap_output_dir=settings.collector.pcap_output.dir,
        pcap_max_file_size_mb=settings.collector.pcap_output.max_file_size_mb,
        pcap_max_file_count=settings.collector.pcap_output.max_file_count,
        tls_keylog_file=settings.collector.tls_keylog.filepath,
        geo_resolver=geo_resolver,
        ipfix_enabled=settings.collector.ipfix.enabled,
        ipfix_host=settings.collector.ipfix.host,
        ipfix_port=settings.collector.ipfix.port,
        ipfix_export_interval=settings.collector.ipfix.export_interval,
    )
    set_pipeline(pipeline)
    await pipeline.start()

    yield

    # 关闭时：停止采集流水线 → 清理存储 → 关闭 GeoIP
    stop_auto_update()
    await pipeline.stop()
    set_pipeline(None)  # type: ignore[arg-type]
    await close_storage()
    close_geo_resolver()


app = FastAPI(
    title=settings.app.title,
    version=settings.app.version,
    lifespan=lifespan,
)

# CORS 中间件（允许前端开发服务器跨域）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册 API 路由
app.include_router(api_router)

# ── 生产模式: serve 前端静态文件 ──────────────
if not settings.app.reload:
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if frontend_dist.is_dir():
        # 挂载静态文件
        app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

        # SPA fallback: 非 API 路径返回 index.html
        @app.exception_handler(404)
        async def not_found_handler(request, exc):
            if request.url.path.startswith("/api") or request.url.path.startswith("/health"):
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
            index = frontend_dist / "index.html"
            if index.exists():
                return FileResponse(str(index))
            return JSONResponse(status_code=404, content={"detail": "Not Found"})

        logger.info("前端静态文件已挂载: %s", frontend_dist)
    else:
        logger.warning("前端构建产物不存在: %s", frontend_dist)


@app.get("/health")
async def health_check():
    """健康检查端点。"""
    pipeline = get_pipeline()
    return {
        "status": "ok",
        "version": settings.app.version,
        "ndpi": pipeline.dpi.is_available if pipeline and pipeline.dpi else False,
        "storage": settings.storage.backend,
        "collector_running": pipeline.is_running if pipeline else False,
    }


def main() -> None:
    """启动 Uvicorn 服务器。"""
    logger.info("=" * 50)
    logger.info("FluxEye v%s 启动", settings.app.version)
    logger.info("存储后端: %s", settings.storage.backend)
    logger.info("采集接口: %s", settings.collector.interface or "(未配置)")
    logger.info("pcap 输出: %s", "已启用" if settings.collector.pcap_output.enabled else "已禁用")
    logger.info("TLS KeyLog: %s", settings.collector.tls_keylog.filepath or "未配置")
    logger.info("监听地址: %s:%d", settings.app.host, settings.app.port)
    logger.info("=" * 50)

    uvicorn.run(
        "app.main:app",
        host=settings.app.host,
        port=settings.app.port,
        reload=settings.app.reload,
        log_level=settings.app.log_level.upper() if settings.app.reload else "warning",
    )


if __name__ == "__main__":
    main()
