"""Pcap 文件写入器 — 将抓取的包保存为 tcpdump/Wireshark 兼容格式。

支持两种模式:
1. **在线写入** — 抓包同时实时写入 pcap 文件（类似 tcpdump -w）
2. **分段写入** — 按时间/大小自动轮转文件（类似 tcpdump -C -W）
"""

from __future__ import annotations

import logging
import os
import struct
import time
from pathlib import Path
from typing import Optional

from app.collector.packet import ParsedPacket

logger = logging.getLogger(__name__)

# PCAP 全局头（小端序, nanosecond 精度）
PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHiIII",
    0xa1b2c3d4,    # magic number (little-endian)
    4,              # version major
    0,              # version minor
    0,              # thiszone (GMT offset)
    0,              # sigfigs (accuracy)
    65535,          # snaplen (max packet length)
    1,              # network (1 = Ethernet)
)


class PcapWriter:
    """pcap 文件写入器，兼容 tcpdump / Wireshark。

    用法:
        writer = PcapWriter("/path/to/output.pcap")
        writer.open()
        writer.write(parsed_packet)
        writer.close()
    """

    def __init__(
        self,
        output_dir: str = "./data/captures",
        filename_prefix: str = "fluxeye",
        max_file_size: int = 100 * 1024 * 1024,  # 100MB 轮转
        max_file_count: int = 10,  # 最多保留 10 个文件
    ):
        self.output_dir = Path(output_dir)
        self.filename_prefix = filename_prefix
        self.max_file_size = max_file_size
        self.max_file_count = max_file_count
        self._file: Optional[BinaryIO] = None
        self._current_path: Optional[Path] = None
        self._current_size = 0
        self._sequence = 0
        self._packets_written = 0

    def open(self) -> None:
        """创建输出目录并打开第一个 pcap 文件。"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._rotate()

    def _rotate(self) -> None:
        """轮转：关闭旧文件，创建新文件。"""
        # 关闭旧文件
        self._close_file()

        # 清理旧文件（保留最后 max_file_count 个）
        self._cleanup_old()

        # 创建新文件
        self._sequence += 1
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"{self.filename_prefix}_{timestamp}_{self._sequence:03d}.pcap"
        self._current_path = self.output_dir / filename
        self._file = open(self._current_path, "wb")
        self._file.write(PCAP_GLOBAL_HEADER)
        self._current_size = len(PCAP_GLOBAL_HEADER)
        logger.info("pcap 文件: %s", self._current_path)

    def _close_file(self) -> None:
        if self._file:
            try:
                self._file.close()
            except OSError:
                pass
            self._file = None
            self._current_size = 0

    def _cleanup_old(self) -> None:
        """删除超出 max_file_count 的旧文件。"""
        try:
            files = sorted(self.output_dir.glob(f"{self.filename_prefix}_*.pcap"))
            while len(files) >= self.max_file_count:
                oldest = files.pop(0)
                oldest.unlink(missing_ok=True)
                logger.info("删除旧 pcap: %s", oldest.name)
        except OSError:
            pass

    def write(self, pkt: ParsedPacket) -> None:
        """写入一个数据包到 pcap 文件。"""
        if self._file is None:
            return

        raw = pkt.raw
        ts = pkt.timestamp.timestamp()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        incl_len = min(len(raw), 65535)

        packet_header = struct.pack(
            "<IIII",
            ts_sec,
            ts_usec,
            incl_len,
            incl_len,
        )

        self._file.write(packet_header)
        self._file.write(raw[:incl_len])
        self._current_size += 16 + incl_len
        self._packets_written += 1

        # 检查是否需要轮转
        if self._current_size >= self.max_file_size:
            self._rotate()

    def flush(self) -> None:
        """刷写缓冲区到磁盘。"""
        if self._file:
            self._file.flush()
            os.fsync(self._file.fileno())

    def close(self) -> None:
        """关闭当前 pcap 文件。"""
        self._close_file()
        logger.info(
            "pcap 写入完成: %d 包, %d 文件",
            self._packets_written,
            self._sequence,
        )

    @property
    def current_file(self) -> Optional[str]:
        return str(self._current_path) if self._current_path else None

    @property
    def packets_written(self) -> int:
        return self._packets_written


# 为类型提示导出的别名
try:
    from typing import BinaryIO
except ImportError:
    from typing import IO as BinaryIO  # fallback
