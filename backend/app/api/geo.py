"""GeoIP 管理 API — 数据库状态查询、配置管理、文件上传与即时更新。"""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, File
from pydantic import BaseModel

from app.config import settings
from app.geo.deps import get_geo_resolver, reload_resolver
from app.utils.logger import get_logger

logger = get_logger("api.geo")

router = APIRouter(prefix="/geo", tags=["geo"])


# ── 响应模型 ───────────────────────────────────────────

class GeoDBFileInfo(BaseModel):
    """单个 GeoIP 数据库文件状态。"""
    edition: str
    path: str
    exists: bool = False
    size_bytes: int = 0
    age_days: float = 0.0
    last_modified: str = ""


class GeoUpdateStatus(BaseModel):
    """GeoIP 整体状态。"""
    available: bool = False
    auto_update: bool = False
    update_interval_days: int = 7
    files: list[GeoDBFileInfo] = []
    last_update_time: str = ""
    updating: bool = False


class GeoConfigInfo(BaseModel):
    """GeoIP 配置信息（license_key 脱敏）。"""
    account_id: str = ""
    license_key: str = ""
    has_account: bool = False
    db_dir: str = ""
    db_files: list[dict] = []


class GeoConfigUpdate(BaseModel):
    """更新 GeoIP 配置请求。"""
    account_id: str = ""
    license_key: str = ""


# ── 全局更新锁 ─────────────────────────────────────────

_updating = False
_update_lock = asyncio.Lock()


def _get_db_dir() -> Path:
    """获取 GeoIP 数据库目录。"""
    return Path(settings.geoip.city_db).parent


def _mask_key(key: str) -> str:
    """脱敏 license key，只显示前4位和后4位。"""
    if len(key) <= 8:
        return "****"
    return key[:4] + "****" + key[-4:]


def _format_bytes(size: int) -> str:
    """格式化字节数。"""
    if size >= 1_000_000:
        return f"{size / 1_000_000:.1f} MB"
    if size >= 1_000:
        return f"{size / 1_000:.1f} KB"
    return f"{size} B"


def _get_file_info(edition_id: str) -> GeoDBFileInfo:
    """获取单个数据库文件的状态。"""
    cfg = settings.geoip

    if "City" in edition_id:
        db_path = Path(cfg.city_db)
    elif "ASN" in edition_id:
        db_path = Path(cfg.asn_db)
    elif "Country" in edition_id:
        db_path = Path(getattr(cfg, 'country_db', str(Path(cfg.city_db).parent / f"{edition_id}.mmdb")))
    else:
        db_path = Path(cfg.city_db).parent / f"{edition_id}.mmdb"

    info = GeoDBFileInfo(
        edition=edition_id,
        path=str(db_path),
    )

    if db_path.exists():
        st = db_path.stat()
        info.exists = True
        info.size_bytes = st.st_size
        info.age_days = round((time.time() - st.st_mtime) / 86_400, 1)
        info.last_modified = datetime.fromtimestamp(
            st.st_mtime, tz=timezone.utc
        ).isoformat()

    return info


def _get_last_update_time() -> str:
    """从版本文件中读取最近更新时间。"""
    output_dir = _get_db_dir()

    latest: float = 0
    for ver_file in output_dir.glob("*.version.txt"):
        try:
            mtime = ver_file.stat().st_mtime
            if mtime > latest:
                latest = mtime
        except OSError:
            pass

    if latest > 0:
        return datetime.fromtimestamp(latest, tz=timezone.utc).isoformat()
    return ""


# ── 端点 ───────────────────────────────────────────────

@router.get("/status", response_model=GeoUpdateStatus)
async def get_geo_status():
    """获取 GeoIP 数据库状态。"""
    global _updating

    resolver = get_geo_resolver()
    files = [_get_file_info(eid) for eid in settings.geoip.edition_ids]

    return GeoUpdateStatus(
        available=resolver.is_available,
        auto_update=settings.geoip.auto_update,
        update_interval_days=settings.geoip.update_interval_days,
        files=files,
        last_update_time=_get_last_update_time(),
        updating=_updating,
    )


@router.get("/config", response_model=GeoConfigInfo)
async def get_geo_config():
    """获取 GeoIP 配置信息（license_key 脱敏）。"""
    db_dir = _get_db_dir()
    db_files = []
    if db_dir.exists():
        for f in sorted(db_dir.iterdir()):
            if f.suffix in (".mmdb", ".tar.gz"):
                db_files.append({
                    "name": f.name,
                    "size_bytes": f.stat().st_size,
                    "modified": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
                })

    aid = settings.geoip.account_id
    lk = settings.geoip.license_key
    return GeoConfigInfo(
        account_id=aid if aid else "",
        license_key=_mask_key(lk) if lk else "",
        has_account=bool(aid and lk),
        db_dir=str(db_dir),
        db_files=db_files,
    )


@router.post("/config")
async def update_geo_config(req: GeoConfigUpdate):
    """更新 GeoIP 配置（同时更新内存中的 settings 和环境变量）。"""
    import os as _os
    if req.account_id:
        settings.geoip.account_id = req.account_id
        _os.environ["FLUXEYE_GEOIP__ACCOUNT_ID"] = req.account_id
    if req.license_key:
        settings.geoip.license_key = req.license_key
        _os.environ["FLUXEYE_GEOIP__LICENSE_KEY"] = req.license_key
    logger.info("GeoIP 配置已更新: account_id=%s", req.account_id)
    return {"message": "GeoIP 配置已更新", "success": True}


@router.get("/databases")
async def list_geo_databases():
    """列出 GeoIP 数据库目录中的所有文件。"""
    db_dir = _get_db_dir()
    if not db_dir.exists():
        return {"files": [], "dir": str(db_dir)}
    files = []
    for f in sorted(db_dir.iterdir()):
        if f.is_file() and f.suffix in (".mmdb", ".tar.gz", ".txt"):
            files.append({
                "name": f.name,
                "size_bytes": f.stat().st_size,
                "size_display": _format_bytes(f.stat().st_size),
                "modified": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
            })
    return {"files": files, "dir": str(db_dir)}


@router.post("/databases/upload")
async def upload_geo_database(file: UploadFile = File(...)):
    """上传 GeoIP 数据库文件。"""
    db_dir = _get_db_dir()
    db_dir.mkdir(parents=True, exist_ok=True)

    if not file.filename:
        raise HTTPException(400, "文件名不能为空")

    # 只允许 .mmdb 和 .tar.gz 文件
    if not (file.filename.endswith(".mmdb") or file.filename.endswith(".tar.gz")):
        raise HTTPException(400, "仅支持 .mmdb 和 .tar.gz 文件")

    dest = db_dir / file.filename

    # 安全校验：防止路径穿越
    try:
        dest = dest.resolve()
        db_dir_resolved = db_dir.resolve()
        if not str(dest).startswith(str(db_dir_resolved)):
            raise HTTPException(400, "非法文件名")
    except (ValueError, OSError):
        raise HTTPException(400, "无效文件名")

    try:
        content = await file.read()
        dest.write_bytes(content)
        logger.info("GeoIP 数据库上传: %s (%d bytes)", file.filename, len(content))

        # 如果是 mmdb 文件，重新加载解析器
        if file.filename.endswith(".mmdb"):
            reload_resolver()

        return {
            "message": f"文件 {file.filename} 上传成功",
            "path": str(dest),
            "size_bytes": len(content),
            "success": True,
        }
    except Exception as e:
        raise HTTPException(500, f"上传失败: {e}")


@router.delete("/databases/{filename:path}")
async def delete_geo_database(filename: str):
    """删除 GeoIP 数据库文件。"""
    db_dir = _get_db_dir()
    file_path = db_dir / filename

    # 安全检查：防止目录遍历
    if not file_path.resolve().is_relative_to(db_dir.resolve()):
        raise HTTPException(400, "非法文件名")

    if not file_path.exists():
        raise HTTPException(404, f"文件不存在: {filename}")

    try:
        file_path.unlink()
        logger.info("GeoIP 数据库删除: %s", filename)
        return {"message": f"文件 {filename} 已删除", "success": True}
    except Exception as e:
        raise HTTPException(500, f"删除失败: {e}")


@router.post("/update")
async def trigger_geo_update():
    """立即触发 GeoIP 数据库更新。

    在后台线程中下载最新数据库，完成后自动重新加载解析器。
    """
    global _updating

    if _updating:
        raise HTTPException(409, "数据库正在更新中，请稍后再试")

    async with _update_lock:
        if _updating:
            raise HTTPException(409, "数据库正在更新中，请稍后再试")

        _updating = True

    try:
        from scripts.download_geoip import download_all  # type: ignore[import-untyped]

        logger.info("手动触发 GeoIP 数据库更新 ...")

        loop = asyncio.get_event_loop()

        def _run():
            download_all()

        await loop.run_in_executor(None, _run)
        # 无论部分失败还是全部成功，都重新加载解析器
        reload_resolver()
        logger.info("GeoIP 数据库更新完成（可能部分跳过），解析器已重新加载")

        return {
            "message": "GeoIP 数据库更新完成",
            "success": True,
        }

    except Exception as e:
        logger.error("GeoIP 更新异常: %s", e)
        raise HTTPException(500, f"GeoIP 更新失败: {e}")

    finally:
        _updating = False
