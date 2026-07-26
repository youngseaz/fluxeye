"""MAC OUI 厂商查询 — 从 IEEE 公共注册表解析设备制造商。

数据来源:
  - MA-L (OUI-24): https://standards-oui.ieee.org/oui/oui.csv
  - MA-M (OUI-28): https://standards-oui.ieee.org/oui28/mam.csv
  - MA-S (OUI-36): https://standards-oui.ieee.org/oui36/mas.csv

用法:
    from app.geo.mac_vendor import lookup_vendor, update_oui_db

    vendor = lookup_vendor("e4:f2:7c:11:22:33")  # → "Juniper Networks"
    update_oui_db()  # 手动更新本地 OUI 数据库
"""

from __future__ import annotations

import csv
import json
import os
import time
from pathlib import Path
from typing import Optional

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("geo.mac_vendor")

# IEEE OUI 下载地址
OUI_CSV_URLS = {
    "MA-L": "https://standards-oui.ieee.org/oui/oui.csv",
    "MA-M": "https://standards-oui.ieee.org/oui28/mam.csv",
    "MA-S": "https://standards-oui.ieee.org/oui36/mas.csv",
}

# 本地缓存文件名
OUI_CACHE_FILE = "oui_vendors.json"

# ── 内存缓存 ───────────────────────────────────────────

_oui_cache: dict[str, str] = {}  # {oui_prefix_upper: vendor_name}
_cache_loaded = False
_cache_timestamp: float = 0.0


def _oui_db_path() -> Path:
    """返回 OUI 缓存数据库路径。"""
    data_dir = Path(settings.storage.sqlite.path).parent if hasattr(settings, "storage") else Path("data")
    return data_dir / OUI_CACHE_FILE


def _normalize_mac(mac: str) -> str:
    """将 MAC 地址格式化为大写无分隔符形式。

    "e4:f2:7c:11:22:33" → "E4F27C112233"
    "e4-f2-7c-11-22-33" → "E4F27C112233"
    "e4f27c112233"       → "E4F27C112233"
    """
    raw = mac.upper().replace(":", "").replace("-", "").replace(".", "")
    return raw


def _oui_prefix(mac: str) -> str:
    """从 MAC 地址提取 OUI 前缀（前 6 个十六进制字符 = 24 位）。

    MA-L (OUI-24): 前 6 字符 → 匹配整个前缀
    MA-M (OUI-28): 前 7 字符 → 匹配前缀[0:7]
    MA-S (OUI-36): 前 9 字符 → 匹配前缀[0:9]
    """
    raw = _normalize_mac(mac)
    prefixes = []
    if len(raw) >= 6:
        prefixes.append(raw[:6])   # MA-L
    if len(raw) >= 7:
        prefixes.append(raw[:7])   # MA-M
    if len(raw) >= 9:
        prefixes.append(raw[:9])   # MA-S
    return prefixes


def lookup_vendor(mac: str) -> str:
    """查询 MAC 地址对应的设备厂商。

    Args:
        mac: MAC 地址，支持各种格式如 "e4:f2:7c:11:22:33"

    Returns:
        厂商名称字符串，未找到返回 "Unknown"
    """
    global _cache_loaded, _cache_timestamp
    if not _cache_loaded:
        _load_cache()
        _cache_loaded = True

    if not _oui_cache:
        return "Unknown"

    prefixes = _oui_prefix(mac)
    for prefix in prefixes:
        if prefix in _oui_cache:
            return _oui_cache[prefix]
    return "Unknown"


def _load_cache() -> None:
    """从本地文件加载 OUI 缓存。"""
    global _cache_timestamp
    path = _oui_db_path()
    if not path.exists():
        logger.info("OUI 缓存文件不存在: %s", path)
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        _oui_cache.update(data.get("vendors", {}))
        _cache_timestamp = data.get("timestamp", 0)
        logger.info("加载 OUI 缓存: %d 条目, 年龄 %.1f 天",
                     len(_oui_cache),
                     (time.time() - _cache_timestamp) / 86400 if _cache_timestamp else 0)
    except Exception as e:
        logger.warning("加载 OUI 缓存失败: %s", e)


def _save_cache() -> None:
    """保存 OUI 缓存到本地文件。"""
    global _cache_timestamp
    _cache_timestamp = time.time()
    path = _oui_db_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "timestamp": _cache_timestamp,
            "vendors": _oui_cache,
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("保存 OUI 缓存: %d 条目 → %s", len(_oui_cache), path)
    except Exception as e:
        logger.warning("保存 OUI 缓存失败: %s", e)


async def update_oui_db() -> dict:
    """从 IEEE 下载最新 OUI CSV 并更新本地缓存。

    返回:
        {"success": bool, "entries": int, "message": str}
    """
    import asyncio
    import aiohttp

    total_entries = 0
    errors = []

    for registry, url in OUI_CSV_URLS.items():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        errors.append(f"{registry}: HTTP {resp.status}")
                        continue
                    text = await resp.text()
                    count = _parse_csv(text, registry)
                    total_entries += count
                    logger.info("已加载 %s: %d 条目", registry, count)
        except Exception as e:
            errors.append(f"{registry}: {e}")
            logger.warning("下载 %s 失败: %s", registry, e)

    if total_entries > 0:
        _save_cache()
        _cache_loaded = True

    if errors:
        return {"success": len(errors) < len(OUI_CSV_URLS),
                "entries": total_entries,
                "message": f"部分失败: {'; '.join(errors)}"}
    return {"success": True, "entries": total_entries, "message": f"已加载 {total_entries} 条 OUI 记录"}


def _parse_csv(text: str, registry: str) -> int:
    """解析 IEEE OUI CSV 文本并更新缓存。"""
    reader = csv.reader(text.splitlines())
    count = 0
    for row in reader:
        if not row or len(row) < 3:
            continue
        if row[0] == "Registry":
            continue  # 跳过表头
        assignment = row[1].strip()
        org_name = row[2].strip()
        if not assignment or not org_name or org_name == "Private":
            continue
        key = assignment.upper()
        # 优先保留已有条目（更具体的匹配优先）
        if key not in _oui_cache:
            _oui_cache[key] = org_name
            count += 1
    return count


def get_cache_stats() -> dict:
    """获取 OUI 缓存统计。"""
    return {
        "entries": len(_oui_cache),
        "last_update": _cache_timestamp,
        "age_days": (time.time() - _cache_timestamp) / 86400 if _cache_timestamp else 0,
        "cache_file": str(_oui_db_path()),
    }


# ── 常用厂商缩写映射 ──────────────────────────────────

# 部分常见厂商名缩写，用于设备画像显示
VENDOR_ALIAS: dict[str, str] = {
    "Cisco Systems, Inc": "Cisco",
    "Cisco Systems": "Cisco",
    "Cisco Meraki": "Meraki",
    "HUAWEI TECHNOLOGIES CO.,LTD": "华为",
    "Hewlett Packard Enterprise": "HPE",
    "HP Inc.": "HP",
    "Intel Corporate": "Intel",
    "Intel Corporation": "Intel",
    "Apple, Inc.": "Apple",
    "Apple Inc.": "Apple",
    "Samsung Electronics Co., Ltd.": "Samsung",
    "Samsung Electronics": "Samsung",
    "Xiaomi Communications Co Ltd": "小米",
    "Xiaomi Inc.": "小米",
    "HONOR Device Co., Ltd.": "荣耀",
    "Honor Device Co., Ltd.": "荣耀",
    "ZTE Corporation": "中兴",
    "zte corporation": "中兴",
    "HTC Corporation": "HTC",
    "HTC Corp.": "HTC",
    "Google, Inc.": "Google",
    "Google LLC": "Google",
    "Amazon Technologies Inc.": "Amazon",
    "Amazon.com Inc": "Amazon",
    "Microsoft Corporation": "Microsoft",
    "Microsoft Corp.": "Microsoft",
    "META PLATFORMS TECHNOLOGIES, LLC": "Meta",
    "Meta Platforms Technologies, LLC": "Meta",
    "Espressif Inc.": "乐鑫(Espressif)",
    "Espressif Incorporated": "乐鑫(Espressif)",
    "Raspberry Pi Foundation": "Raspberry Pi",
    "Raspberry Pi Trading Ltd": "Raspberry Pi",
    "Shenzhen Hailin Technology Co., Ltd.": "海林科技",
    "TP-Link Corporation Limited": "TP-Link",
    "TP-LINK TECHNOLOGIES CO., LTD.": "TP-Link",
    "Tp-Link Technologies Co., Ltd.": "TP-Link",
    "Xiaomi Communications Co., Ltd.": "小米",
    "Zhejiang Dahua Technology Co., Ltd.": "大华",
    "ZHEJIANG DAHUA TECHNOLOGY CO., LTD": "大华",
    "Hangzhou Hikvision Digital Technology Co., Ltd.": "海康威视",
    "Hikvision Digital Technology Co., Ltd.": "海康威视",
    "Juniper Networks": "Juniper",
    "Nokia Solutions and Networks": "Nokia",
    "Nokia Shanghai Bell Co., Ltd.": "Nokia",
    "Fiberhome Telecommunication Technologies Co.,LTD": "烽火",
    "New H3C Technologies Co., Ltd": "新华三(H3C)",
}


def vendor_alias(name: str) -> str:
    """获取厂商简称。"""
    return VENDOR_ALIAS.get(name, name)
