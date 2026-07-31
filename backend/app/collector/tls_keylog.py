"""TLS Key Log 解析器 — 解析 SSLKEYLOGFILE 格式的密钥文件。

SSLKEYLOGFILE 是 NSS (Firefox/Chrome/curl) 导出的 TLS 会话密钥文件。
与 Wireshark 兼容，可用于离线解密 TLS 流量。

格式:
  # 注释行
  CLIENT_RANDLE <hex_client_random> <hex_master_secret>
  CLIENT_EARLY_TRAFFIC_SECRET <hex_client_random> <hex_secret>
  SERVER_HANDSHAKE_TRAFFIC_SECRET <hex_client_random> <hex_secret>
  CLIENT_HANDSHAKE_TRAFFIC_SECRET <hex_client_random> <hex_secret>
  SERVER_TRAFFIC_SECRET_0 <hex_client_random> <hex_secret>
  CLIENT_TRAFFIC_SECRET_0 <hex_client_random> <hex_secret>
  RSA <premaster_key_hex>
  EXTRACT_SECRETS <hex> <label>
  LABELED_MACHINE <hex_client_random> <hex_secret>

用法:
    # 浏览器启动前设置环境变量
    export SSLKEYLOGFILE=/tmp/tls_keys.log
    firefox

    # FluxEye 配置
    collector:
      tls_keylog_file: /tmp/tls_keys.log
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.utils.logger import get_logger

logger = get_logger("collector.tls_keylog")

# ── 密钥记录 ──────────────────────────────────────────

@dataclass
class TLSKeyEntry:
    """一条 TLS 密钥记录。"""
    label: str           # CLIENT_RANDOM, RSA, etc.
    client_random: str   # 十六进制 client random
    secret: str          # 十六进制密钥数据


class TLSKeyLogParser:
    """SSLKEYLOGFILE 解析器。

    支持热加载 — 检测文件变更后增量读取新行。
    """

    LINE_PATTERN = re.compile(
        r"^(?P<label>[A-Z_]+)\s+"
        r"(?P<random>[0-9a-fA-F]+)"
        r"(?:\s+(?P<secret>[0-9a-fA-F]+))?"
    )

    def __init__(self, filepath: str = ""):
        self.filepath = filepath
        self._keys: dict[str, TLSKeyEntry] = {}
        self._last_position = 0
        self._file: Optional[BinaryIO] = None
        self._available = False
        self._watch_enabled = False

    def load(self) -> bool:
        """加载密钥文件。

        Returns:
            True 表示文件存在且可读。
        """
        if not self.filepath:
            return False

        path = Path(self.filepath)
        if not path.exists():
            logger.warning("SSLKEYLOGFILE 不存在: %s", self.filepath)
            return False

        self._available = True
        logger.info("TLS Key Log 已加载: %s", self.filepath)
        return True

    def reload(self) -> int:
        """增量读取新行，返回新增密钥数。"""
        if not self._available or not self.filepath:
            return 0

        try:
            with open(self.filepath, "r") as f:
                f.seek(self._last_position)
                new_count = 0
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    match = self.LINE_PATTERN.match(line)
                    if match:
                        entry = TLSKeyEntry(
                            label=match.group("label"),
                            client_random=match.group("random"),
                            secret=match.group("secret") or "",
                        )
                        # 以 client_random 为 key 存储
                        key = entry.client_random
                        if key not in self._keys:
                            self._keys[key] = entry
                            new_count += 1

                self._last_position = f.tell()

            if new_count > 0:
                logger.debug("TLS Key Log: 新增 %d 条密钥", new_count)
            return new_count

        except (OSError, PermissionError) as e:
            logger.error("读取 SSLKEYLOGFILE 失败: %s", e)
            return 0

    def lookup(self, client_random_hex: str) -> Optional[TLSKeyEntry]:
        """根据 client_random 查找密钥。"""
        return self._keys.get(client_random_hex.lower())

    def find_by_label(self, label: str) -> list[TLSKeyEntry]:
        """按标签查找。"""
        return [e for e in self._keys.values() if e.label == label]

    def export_to_wireshark_format(self) -> str:
        """导出为标准 SSLKEYLOGFILE 格式（供 Wireshark 使用）。"""
        lines = ["# FluxEye exported TLS keys"]
        for entry in self._keys.values():
            parts = [entry.label, entry.client_random]
            if entry.secret:
                parts.append(entry.secret)
            lines.append(" ".join(parts))
        return "\n".join(lines)

    @property
    def key_count(self) -> int:
        return len(self._keys)

    @property
    def is_available(self) -> bool:
        return self._available


# ── 简化的 TLS 会话信息 ──────────────────────────────

@dataclass
class TLSSessionInfo:
    """从 DPI 和 Key Log 中提取的 TLS 会话信息。"""
    sni: str = ""                    # Server Name Indication
    ja3: str = ""                    # JA3 指纹
    ja3s: str = ""                   # JA3S 指纹
    cipher_suite: int = 0            # 协商的加密套件
    tls_version: str = ""            # TLS 版本 (1.2, 1.3)
    client_random: str = ""          # Client Random (hex)
    session_id: str = ""             # Session ID (hex)
    keylog_available: bool = False   # 是否有对应的密钥
    certificate: str = ""            # 证书信息 (CN 等)


# ── 环境变量自动检测 ─────────────────────────────────

def detect_keylog_from_env() -> str:
    """从 SSLKEYLOGFILE 环境变量读取路径。"""
    return os.environ.get("SSLKEYLOGFILE", "")


def create_keylog_parser(filepath: str = "") -> TLSKeyLogParser:
    """创建并初始化 TLS Key Log 解析器。

    优先使用传入路径，否则从 SSLKEYLOGFILE 环境变量读取。
    """
    if not filepath:
        filepath = detect_keylog_from_env()

    parser = TLSKeyLogParser(filepath=filepath)
    parser.load()
    if parser.is_available:
        parser.reload()
    return parser


# 为类型提示导出的别名
try:
    from typing import BinaryIO
except ImportError:
    from typing import IO as BinaryIO  # fallback
