"""PCAP 报文提取工具 — 从 pcap 文件中提取指定流的数据包。"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional


PACKET_HEADER_FMT = "<IIII"  # ts_sec, ts_usec, incl_len, orig_len
PACKET_HEADER_SIZE = 16


def extract_flow_packets(
    pcap_path: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    l4_proto: str,
    max_packets: int = 50,
) -> list[dict]:
    """从 pcap 文件中提取指定 5-tuple 流的所有数据包。

    返回按时间排序的包列表，每包包含:
        - timestamp: ISO 时间戳
        - raw_hex: 原始报文 hex 字符串
        - length: 包长度
        - summary: 简要描述（IP 层以上）
    """
    path = Path(pcap_path)
    if not path.exists():
        return []

    packets: list[dict] = []
    try:
        with open(path, "rb") as f:
            # 跳过 pcap 全局头 (24 bytes)
            global_header = f.read(24)
            if len(global_header) < 24:
                return []

            while len(packets) < max_packets:
                header = f.read(PACKET_HEADER_SIZE)
                if len(header) < PACKET_HEADER_SIZE:
                    break

                ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
                    PACKET_HEADER_FMT, header
                )

                if incl_len > 65535 or incl_len < 0:
                    f.seek(incl_len, 1)  # type: ignore[arg-type]
                    continue

                raw = f.read(incl_len)
                if len(raw) < incl_len:
                    break

                # 解析以太网帧
                pkt_info = _match_flow(raw, src_ip, dst_ip, src_port, dst_port, l4_proto)
                if pkt_info:
                    ts = ts_sec + ts_usec / 1_000_000
                    packets.append({
                        "timestamp": ts,
                        "raw_hex": raw.hex(),
                        "length": incl_len,
                        "summary": pkt_info,
                    })
    except (OSError, struct.error):
        return []

    return packets


def _match_flow(
    raw: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    l4_proto: str,
) -> Optional[str]:
    """解析以太网帧，匹配 5-tuple，返回报文摘要。"""
    try:
        if len(raw) < 14:
            return None

        # 以太网头
        eth_type = (raw[12] << 8) | raw[13]

        ip_offset = 14
        if eth_type == 0x8100:  # VLAN
            ip_offset = 18
            if len(raw) < ip_offset:
                return None
            eth_type = (raw[16] << 8) | raw[17]

        if eth_type == 0x0800:  # IPv4
            if len(raw) < ip_offset + 20:
                return None
            version_ihl = raw[ip_offset]
            ihl = (version_ihl & 0x0F) * 4
            if ihl < 20:
                return None

            pkt_src = f"{raw[ip_offset+12]}.{raw[ip_offset+13]}.{raw[ip_offset+14]}.{raw[ip_offset+15]}"
            pkt_dst = f"{raw[ip_offset+16]}.{raw[ip_offset+17]}.{raw[ip_offset+18]}.{raw[ip_offset+19]}"
            proto = raw[ip_offset + 9]

            # 检查 IP 是否匹配（双向）
            ip_match = (pkt_src == src_ip and pkt_dst == dst_ip) or \
                       (pkt_src == dst_ip and pkt_dst == src_ip)
            if not ip_match:
                return None

            l4_offset = ip_offset + ihl
            is_reverse = (pkt_src == dst_ip and pkt_dst == src_ip)

            if proto == 6:  # TCP
                if len(raw) < l4_offset + 4:
                    return None
                pkt_sport = (raw[l4_offset] << 8) | raw[l4_offset + 1]
                pkt_dport = (raw[l4_offset + 2] << 8) | raw[l4_offset + 3]
                port_match = (pkt_sport == src_port and pkt_dport == dst_port) or \
                             (pkt_sport == dst_port and pkt_dport == src_port)
                if not port_match:
                    return None
                is_reverse = is_reverse or (pkt_sport == dst_port and pkt_dport == src_port)
                direction = "← 入" if is_reverse else "→ 出"
                return f"{direction} TCP len={len(raw)}"

            elif proto == 17:  # UDP
                if len(raw) < l4_offset + 4:
                    return None
                pkt_sport = (raw[l4_offset] << 8) | raw[l4_offset + 1]
                pkt_dport = (raw[l4_offset + 2] << 8) | raw[l4_offset + 3]
                port_match = (pkt_sport == src_port and pkt_dport == dst_port) or \
                             (pkt_sport == dst_port and pkt_dport == src_port)
                if not port_match:
                    return None
                is_reverse = is_reverse or (pkt_sport == dst_port and pkt_dport == src_port)
                direction = "← 入" if is_reverse else "→ 出"
                return f"{direction} UDP len={len(raw)}"

            else:
                direction = "← 入" if is_reverse else "→ 出"
                return f"{direction} IP proto={proto} len={len(raw)}"

        elif eth_type == 0x86DD:  # IPv6
            return "IPv6 packet (unsupported)"

    except (IndexError, ValueError):
        pass

    return None
