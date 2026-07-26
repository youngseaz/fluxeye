"""数据包捕获 — 基于 Linux AF_PACKET 原始套接字。

无需任何第三方依赖，直接通过底层套接字捕获二层数据包。
支持 BPF 过滤和混杂模式。

模式:
1. **在线模式** — 从指定网卡实时抓包 (需要 root / CAP_NET_RAW)
2. **离线模式** — 从 pcap 文件读取 (仅开发/调试)
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import socket
import struct
from typing import AsyncIterator, Optional

from app.collector.packet import ParsedPacket, parse_packet
from app.utils.logger import get_logger

logger = get_logger("collector.capture")

# Linux AF_PACKET 常量
ETH_P_ALL = 0x0003
SIOCGIFINDEX = 0x8933
SIOCGIFFLAGS = 0x8913
IFF_PROMISC = 0x100
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
PACKET_FANOUT = 18
PACKET_FANOUT_HASH = 0


class PacketCapture:
    """基于 AF_PACKET 的网络抓包器。

    使用 Linux 原始套接字直接读取二层数据包。
    需要 CAP_NET_RAW 或 root 权限。
    """

    def __init__(self, interface: str = "", bpf_filter: str = "",
                 snap_len: int = 65535, promisc: bool = True):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snap_len = snap_len
        self.promisc = promisc
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._packet_count = 0

    def _get_iface_index(self) -> int:
        """获取网络接口的索引。"""
        if not self.interface:
            return 0  # 所有接口
        ifreq = struct.pack("16si", self.interface.encode()[:16], 0)
        try:
            result = struct.unpack("16si",
                fcntl.ioctl(self._sock.fileno(), SIOCGIFINDEX, ifreq))[1]
            return result
        except OSError as e:
            raise RuntimeError(f"接口 {self.interface} 不存在: {e}") from e

    def _enable_promisc(self) -> None:
        """启用混杂模式。"""
        if not self.interface:
            return
        ifreq = struct.pack("16sh", self.interface.encode()[:16], 0)
        flags = struct.unpack("16sh",
            fcntl.ioctl(self._sock.fileno(), SIOCGIFFLAGS, ifreq))[1]
        if not (flags & IFF_PROMISC):
            ifreq = struct.pack("16sh", self.interface.encode()[:16],
                                flags | IFF_PROMISC)
            fcntl.ioctl(self._sock.fileno(), SIOCGIFFLAGS, ifreq)

    def open(self) -> None:
        """打开 AF_PACKET 套接字。"""
        try:
            self._sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL),
            )
            if self.interface:
                iface_idx = self._get_iface_index()
                self._sock.bind((self.interface, ETH_P_ALL))
                logger.info("绑定接口: %s (index=%d)", self.interface, iface_idx)
            else:
                logger.info("抓取所有接口")

            if self.promisc:
                self._enable_promisc()
                logger.info("已启用混杂模式")

            # 设置接收超时
            self._sock.settimeout(1.0)

            # 增大接收缓冲区
            bufsize = 64 * 1024 * 1024  # 64 MB
            try:
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, bufsize)
            except OSError:
                pass

            self._running = True

        except PermissionError:
            raise RuntimeError(
                "缺少权限: 需要 CAP_NET_RAW 或 root 权限来打开原始套接字"
            )

    def close(self) -> None:
        """关闭抓包套接字。"""
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def recv(self) -> Optional[ParsedPacket]:
        """同步接收一个数据包并解析。"""
        if not self._sock or not self._running:
            return None
        try:
            data = self._sock.recv(self.snap_len)
            self._packet_count += 1
            pkt = parse_packet(data)
            if pkt:
                pkt.interface = self.interface
            return pkt
        except socket.timeout:
            return None
        except OSError as e:
            logger.error("抓包错误: %s", e)
            return None

    async def recv_async(self) -> Optional[ParsedPacket]:
        """异步接收一个数据包。"""
        return await asyncio.get_event_loop().run_in_executor(None, self.recv)

    async def stream(self) -> AsyncIterator[ParsedPacket]:
        """异步迭代器：持续产出 ParsedPacket。"""
        self.open()
        try:
            while self._running:
                pkt = await self.recv_async()
                if pkt is not None:
                    yield pkt
        finally:
            self.close()

    def stop(self) -> None:
        """停止抓包。"""
        self.close()

    @property
    def packet_count(self) -> int:
        return self._packet_count

    @property
    def is_running(self) -> bool:
        return self._running and self._sock is not None


# ── Pcap 文件回放（开发/调试用）────────────────────────

class PcapReader:
    """读取 .pcap 文件用于离线回放。"""

    PCAP_MAGIC_BIG_ENDIAN = b"\xa1\xb2\xc3\xd4"
    PCAP_MAGIC_LITTLE_ENDIAN = b"\xd4\xc3\xb2\xa1"

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = None
        self._little_endian = False
        self._link_type = 0

    def open(self) -> None:
        """打开并解析 pcap 文件头。"""
        import struct

        self._file = open(self.filepath, "rb")
        header = self._file.read(24)
        if len(header) < 24:
            raise ValueError("无效的 pcap 文件")

        magic = header[:4]
        if magic == self.PCAP_MAGIC_BIG_ENDIAN:
            self._little_endian = False
        elif magic == self.PCAP_MAGIC_LITTLE_ENDIAN:
            self._little_endian = True
        else:
            raise ValueError(f"不是 pcap 文件 (magic={magic.hex()})")

        # 读取链路层类型 (offset 20)
        if self._little_endian:
            self._link_type = struct.unpack("<I", header[20:24])[0]
        else:
            self._link_type = struct.unpack(">I", header[20:24])[0]

    def __iter__(self) -> "PcapReader":
        return self

    def __next__(self) -> ParsedPacket:
        """读取下一个数据包。"""
        import struct

        if self._file is None:
            raise StopIteration

        header = self._file.read(16)
        if len(header) < 16:
            self._file.close()
            self._file = None
            raise StopIteration

        fmt = "<IIII" if self._little_endian else ">IIII"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, header)

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            self._file.close()
            self._file = None
            raise StopIteration

        ts = ts_sec + ts_usec / 1_000_000
        pkt = parse_packet(data, ts)
        if pkt is None:
            return self.__next__()  # 跳过非 IPv4 包
        return pkt

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None
