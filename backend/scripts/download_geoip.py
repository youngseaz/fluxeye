#!/usr/bin/env python3
"""MaxMind GeoLite2 数据库下载工具 — 纯 Python 实现。

用法:
    # 使用配置文件中的凭证
    python scripts/download_geoip.py

    # 或指定凭证
    python scripts/download_geoip.py --account-id 123456 --license-key abc123

    # 仅检查最新版本
    python scripts/download_geoip.py --check
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

# 将项目根目录加入 sys.path，以便导入 app.config
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("scripts.download_geoip")


# ── Edition → 输出文件名映射 ───────────────────────────

EDITION_OUTPUT_MAP: dict[str, str] = {
    "GeoLite2-City":    "GeoLite2-City",
    "GeoLite2-ASN":     "GeoLite2-ASN",
    "GeoLite2-Country": "GeoLite2-Country",
}


def download_edition(
    edition_id: str,
    account_id: str,
    license_key: str,
    output_dir: Path,
    check_only: bool = False,
) -> bool:
    """下载指定的 GeoLite2 数据库版本。

    Args:
        edition_id: 版本 ID，如 "GeoLite2-City"
        account_id: MaxMind 账号 ID
        license_key: MaxMind License Key
        output_dir: 输出目录
        check_only: 仅检查最新版本日期

    Returns:
        下载成功返回 True，否则 False
    """
    import urllib.request
    import urllib.error

    url = (
        f"https://download.maxmind.com/geoip/databases/{edition_id}"
        f"/download?suffix=tar.gz"
    )

    # 构造 Basic Auth 请求
    import base64
    auth_str = f"{account_id}:{license_key}"
    auth_bytes = auth_str.encode("utf-8")
    auth_b64 = base64.b64encode(auth_bytes).decode("ascii")

    output_name = EDITION_OUTPUT_MAP.get(edition_id, edition_id)
    output_path = output_dir / f"{output_name}.mmdb"
    version_file = output_dir / f"{output_name}.version.txt"

    print(f"[{edition_id}] 正在连接 MaxMind ...")

    try:
        if check_only:
            # HEAD 请求检查 Last-Modified (不消耗下载配额)
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("Authorization", f"Basic {auth_b64}")
            with urllib.request.urlopen(req) as resp:
                last_modified = resp.headers.get("Last-Modified", "未知")
                content_disp = resp.headers.get("Content-Disposition", "未知")
                print(f"  Last-Modified: {last_modified}")
                print(f"  Content-Disposition: {content_disp}")
            return True

        # GET 请求下载
        print(f"  下载中 ...")

        # 第一步: 不跟随重定向，获取 R2 presigned URL
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        redirect_opener = urllib.request.build_opener(NoRedirect)
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {auth_b64}")
        req.add_header("User-Agent", "curl/8.5.0")

        try:
            with redirect_opener.open(req) as resp:
                r2_url = resp.headers.get("Location", "")
                if not r2_url or resp.status != 302:
                    print(f"  ❌ 未收到重定向 (HTTP {resp.status})")
                    return False
        except urllib.error.HTTPError as e:
            if e.code == 302:
                r2_url = e.headers.get("Location", "")
                if not r2_url:
                    print(f"  ❌ 重定向响应中缺少 Location 头")
                    return False
            elif e.code == 451:
                print(f"  ⚠️  HTTP 451: 该数据库在当前区域不可用 (法律限制)，已跳过")
                return True  # 非致命错误，返回 True 表示跳过
            else:
                print(f"  ❌ HTTP {e.code}: {e.reason}")
                if e.code == 401:
                    print("     认证失败，请检查 AccountID 和 License Key")
                elif e.code == 404:
                    print(f"     版本 '{edition_id}' 不存在")
                return False

        # 第二步: 直接访问 R2 presigned URL (不带 Authorization header)
        req2 = urllib.request.Request(r2_url)
        req2.add_header("User-Agent", "curl/8.5.0")
        try:
            with urllib.request.urlopen(req2) as resp:
                data = resp.read()
        except Exception as e:
            print(f"  ❌ 下载失败: {e}")
            return False

        size_mb = len(data) / (1024 * 1024)
        print(f"  收到 {len(data)} bytes ({size_mb:.1f} MB)")

        # 解压 tar.gz — 找到 .mmdb 文件
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            mmdb_member = None
            for member in tar.getmembers():
                if member.name.endswith(".mmdb") and not member.isdir():
                    mmdb_member = member
                    break

            if mmdb_member is None:
                print(f"  ❌ 压缩包中未找到 .mmdb 文件")
                return False

            # 提取到临时路径再 rename，避免部分写入
            tmp_path = output_path.with_suffix(".tmp")
            with open(tmp_path, "wb") as f:
                f.write(tar.extractfile(mmdb_member).read())
            tmp_path.rename(output_path)

        # 记录版本信息
        now_iso = datetime.now(timezone.utc).isoformat()
        with open(version_file, "w") as f:
            f.write(f"edition_id={edition_id}\n")
            f.write(f"download_time={now_iso}\n")
            f.write(f"size_bytes={len(data)}\n")

        print(f"  ✅ {output_path}  ({size_mb:.1f} MB)")
        return True

    except urllib.error.HTTPError as e:
        if e.code == 451:
            print(f"  ⚠️  HTTP 451: 该数据库在当前区域不可用 (法律限制)，已跳过")
            return True  # 非致命错误
        print(f"  ❌ HTTP {e.code}: {e.reason}")
        if e.code == 401:
            print("     认证失败，请检查 AccountID 和 License Key")
        elif e.code == 404:
            print(f"     版本 '{edition_id}' 不存在")
        return False
    except Exception as e:
        print(f"  ❌ {e}")
        return False


def get_db_age_days(db_path: Path) -> float | None:
    """获取数据库文件的年龄（天数），文件不存在返回 None。"""
    if not db_path.exists():
        return None
    mtime = db_path.stat().st_mtime
    age = (time.time() - mtime) / 86400
    return age


def needs_update(
    db_path: Path,
    max_age_days: int = 7,
) -> bool:
    """检查数据库是否需要更新。"""
    age = get_db_age_days(db_path)
    if age is None:
        return True
    return age > max_age_days


def download_all(
    account_id: str | None = None,
    license_key: str | None = None,
    check_only: bool = False,
) -> bool:
    """下载/检查所有配置的 GeoIP 数据库。"""
    cfg = settings.geoip
    aid = account_id or cfg.account_id
    lk = license_key or cfg.license_key

    if not aid or not lk:
        print("错误: 未设置 AccountID 和 License Key")
        print("请在 config/config.yaml 的 geoip 节中配置，或通过 --account-id / --license-key 参数传入")
        return False

    editions = cfg.edition_ids
    output_dir = Path(cfg.city_db).parent.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"MaxMind GeoLite2 数据库下载")
    print(f"{'='*50}")
    print(f"账号 ID: {aid}")
    print(f"数据目录: {output_dir}")
    if check_only:
        print(f"模式: 仅检查版本")
    print()

    all_ok = True
    for i, edition in enumerate(editions, 1):
        print(f"[{i}/{len(editions)}] {edition}")
        ok = download_edition(
            edition_id=edition,
            account_id=aid,
            license_key=lk,
            output_dir=output_dir,
            check_only=check_only,
        )
        if not ok:
            all_ok = False
        print()

    if not check_only:
        success_count = 0
        for f in sorted(output_dir.glob("*.mmdb")):
            size_mb = f.stat().st_size / (1024 * 1024)
            print(f"  {f.name}: {size_mb:.1f} MB")
            success_count += 1

        if all_ok:
            print("✅ 所有数据库下载完成")
        else:
            print(f"⚠️  部分数据库下载失败（成功 {success_count}/{len(editions)}，可忽略）")

    return True  # 即使部分失败也返回成功，避免阻断自动更新流程


# ── 命令行入口 ─────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="MaxMind GeoLite2 数据库下载工具"
    )
    parser.add_argument(
        "--account-id",
        help="MaxMind 账号 ID (默认从 config.yaml 读取)",
    )
    parser.add_argument(
        "--license-key",
        help="MaxMind License Key (默认从 config.yaml 读取)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="仅检查最新版本日期，不下载",
    )
    args = parser.parse_args()

    success = download_all(
        account_id=args.account_id,
        license_key=args.license_key,
        check_only=args.check,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
