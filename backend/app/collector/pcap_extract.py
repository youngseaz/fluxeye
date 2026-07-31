"""PCAP 报文提取工具 — 从 pcap 文件中提取指定流的数据包。"""

from __future__ import annotations

import ipaddress
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


def _parse_ip_packet(raw: bytes, ip_offset: int):
    """Parse IPv4/IPv6 + TCP headers, return TCP info dict or None.

    Returns dict with: src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload
    """
    try:
        if len(raw) < ip_offset + 2:
            return None
        version = (raw[ip_offset] >> 4) & 0x0F

        if version == 4:  # IPv4
            if len(raw) < ip_offset + 20:
                return None
            ihl = (raw[ip_offset] & 0x0F) * 4
            if ihl < 20:
                return None
            pkt_src = ".".join(str(raw[ip_offset + i]) for i in range(12, 16))
            pkt_dst = ".".join(str(raw[ip_offset + i]) for i in range(16, 20))
            l4_proto = raw[ip_offset + 9]
            l4_offset = ip_offset + ihl

        elif version == 6:  # IPv6
            if len(raw) < ip_offset + 40:
                return None
            pkt_src = _ipv6_bytes_to_str(raw[ip_offset + 8:ip_offset + 24])
            pkt_dst = _ipv6_bytes_to_str(raw[ip_offset + 24:ip_offset + 40])
            l4_proto = raw[ip_offset + 6]
            l4_offset = ip_offset + 40
            # 跳过 IPv6 扩展头，找到真正的 L4 协议
            while l4_proto in (0, 43, 44, 60, 135):  # Hop-by-Hop, Routing, Fragment, Dest-Opts, Mobility
                if l4_offset + 8 > len(raw):
                    return None
                if l4_proto == 44:  # Fragment header 固定 8 字节
                    l4_proto = raw[l4_offset]
                    l4_offset += 8
                else:
                    ext_len = (raw[l4_offset + 1] + 1) * 8 if l4_offset + 1 < len(raw) else 0
                    l4_proto = raw[l4_offset]
                    l4_offset += ext_len if ext_len > 0 else 8
                if l4_offset >= len(raw):
                    return None
        else:
            return None

        if l4_proto not in (6, 17, 132):  # TCP / UDP / SCTP
            return None

        # 公共部分：取端口
        if len(raw) < l4_offset + 4:
            return None
        sport = (raw[l4_offset] << 8) | raw[l4_offset + 1]
        dport = (raw[l4_offset + 2] << 8) | raw[l4_offset + 3]

        if l4_proto == 6:  # TCP
            if len(raw) < l4_offset + 14:
                return None
            seq = struct.unpack(">I", raw[l4_offset + 4:l4_offset + 8])[0]
            ack = struct.unpack(">I", raw[l4_offset + 8:l4_offset + 12])[0]
            data_offset = (raw[l4_offset + 12] >> 4) * 4
            flags = raw[l4_offset + 13]
            if data_offset < 20 or len(raw) < l4_offset + data_offset:
                return None
            payload = raw[l4_offset + data_offset:]
            return {
                "src_ip": pkt_src, "dst_ip": pkt_dst,
                "src_port": sport, "dst_port": dport,
                "seq": seq, "ack": ack, "flags": flags,
                "payload": payload, "is_tcp": True,
                "segments": [{"tsn": seq, "data": payload}] if payload else [],
            }

        elif l4_proto == 17:  # UDP
            if len(raw) < l4_offset + 8:
                return None
            payload = raw[l4_offset + 8:]
            return {
                "src_ip": pkt_src, "dst_ip": pkt_dst,
                "src_port": sport, "dst_port": dport,
                "seq": 0, "ack": 0, "flags": 0,
                "payload": payload, "is_tcp": False,
                "segments": [{"tsn": 0, "data": payload}] if payload else [],
            }

        else:  # SCTP (proto=132)
            # SCTP 公共头: 12 bytes
            if len(raw) < l4_offset + 12:
                return None
            verification_tag = struct.unpack(">I", raw[l4_offset + 4:l4_offset + 8])[0]
            # 解析 Chunks，提取 DATA chunk (type=0) 的 TSN + 用户数据
            chunks_data: list[dict] = []
            chunk_off = l4_offset + 12
            while chunk_off + 4 <= len(raw):
                chunk_type = raw[chunk_off]
                chunk_flags = raw[chunk_off + 1]
                chunk_len = struct.unpack(">H", raw[chunk_off + 2:chunk_off + 4])[0]
                if chunk_len < 4 or chunk_off + chunk_len > len(raw):
                    break
                if chunk_type == 0:  # DATA chunk
                    # DATA: tsn(4) + stream_id(2) + stream_seq(2) + payload_proto(4) + user_data
                    if chunk_len >= 16:
                        tsn = struct.unpack(">I", raw[chunk_off + 4:chunk_off + 8])[0]
                        user_data = raw[chunk_off + 16:chunk_off + chunk_len]
                        if user_data:
                            chunks_data.append({"tsn": tsn, "data": user_data})
                # chunk 按 4 字节对齐
                padded = (chunk_len + 3) & ~3
                chunk_off += padded

            all_payload = b"".join(c["data"] for c in chunks_data) if chunks_data else b""
            return {
                "src_ip": pkt_src, "dst_ip": pkt_dst,
                "src_port": sport, "dst_port": dport,
                "seq": verification_tag, "ack": 0, "flags": 0,
                "payload": all_payload, "is_tcp": False,
                "segments": chunks_data,
            }
    except (IndexError, ValueError):
        return None


def _ipv6_bytes_to_str(addr_bytes: bytes) -> str:
    """将 16 字节 IPv6 地址转为标准字符串格式。"""
    return str(ipaddress.IPv6Address(addr_bytes))


def reassemble_stream(
    pcap_path: str,
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    l4_proto: str = "tcp",
    max_bytes: int = 131072,
) -> dict:
    """从 pcap 文件中重组 TCP/UDP 流（类似 Wireshark Follow Stream）。

    TCP 模式：
    1. 遍历 pcap 中所有匹配 5-tuple 的 TCP 包
    2. 按 sequence number 排序，去除重传（同 seq 同长度）
    3. 去除各层协议头，只保留 payload
    4. 按方向分别拼接为完整数据流

    UDP 模式：
    1. 收集所有匹配 5-tuple 的 UDP 包
    2. 按时间戳排序
    3. 每个 datagram 的 payload 独立，直接拼接

    Args:
        pcap_path: pcap 文件路径
        src_ip, dst_ip, src_port, dst_port: 5-tuple
        l4_proto: "tcp" 或 "udp"
        max_bytes: 每个方向最大返回字节数

    Returns:
        dict with:
            - client_data: bytes (C→S 数据)
            - server_data: bytes (S→C 数据)
            - client_packets: int
            - server_packets: int
            - client_raw: str (hex)
            - server_raw: str (hex)
            - total_bytes: int
            - stream_closed: bool (TCP FIN/RST)
            - error: str
    """
    is_tcp = l4_proto.lower() == "tcp"
    is_sctp = l4_proto.lower() == "sctp"
    path = Path(pcap_path)
    if not path.exists():
        return {"error": "pcap 文件不存在"}

    segments: list[dict] = []
    try:
        with open(path, "rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                return {"error": "无效的 pcap 文件"}

            while True:
                header = f.read(PACKET_HEADER_SIZE)
                if len(header) < PACKET_HEADER_SIZE:
                    break
                ts_sec, ts_usec, incl_len, _ = struct.unpack(PACKET_HEADER_FMT, header)
                if incl_len > 65535 or incl_len <= 0:
                    f.seek(incl_len, 1)
                    continue
                raw = f.read(incl_len)
                if len(raw) < incl_len:
                    break

                if len(raw) < 14:
                    continue
                eth_type = (raw[12] << 8) | raw[13]
                ip_off = 14
                if eth_type == 0x8100:  # VLAN
                    ip_off = 18
                    if len(raw) < ip_off:
                        continue
                    eth_type = (raw[16] << 8) | raw[17]

                if eth_type not in (0x0800, 0x86DD):
                    continue

                pkt = _parse_ip_packet(raw, ip_off)
                if not pkt:
                    continue
                if is_tcp and not pkt["is_tcp"]:
                    continue
                if not is_tcp and pkt["is_tcp"]:
                    continue

                ip_match = (pkt["src_ip"] == src_ip and pkt["dst_ip"] == dst_ip) or \
                           (pkt["src_ip"] == dst_ip and pkt["dst_ip"] == src_ip)
                if not ip_match:
                    continue
                port_match = (pkt["src_port"] == src_port and pkt["dst_port"] == dst_port) or \
                             (pkt["src_port"] == dst_port and pkt["dst_port"] == src_port)
                if not port_match:
                    continue

                is_client = (pkt["src_ip"] == src_ip and pkt["src_port"] == src_port)
                ts = ts_sec + ts_usec / 1_000_000

                # SCTP: 按 DATA chunk 的 TSN 拆分为多个 segment
                if is_sctp:
                    for seg in pkt.get("segments", []):
                        segments.append({
                            "tsn": seg["tsn"],
                            "payload": seg["data"],
                            "len": len(seg["data"]),
                            "is_client": is_client,
                            "flags": 0,
                            "ts": ts,
                        })
                else:
                    segments.append({
                        "seq": pkt["seq"],
                        "payload": pkt["payload"],
                        "len": len(pkt["payload"]),
                        "is_client": is_client,
                        "flags": pkt["flags"],
                        "ts": ts,
                    })
    except (OSError, struct.error) as e:
        return {"error": str(e)}

    if not segments:
        return {"error": "未找到匹配的数据包"}

    if is_tcp:
        # TCP: 按 sequence number 排序，去除重传
        segments.sort(key=lambda s: (s["seq"], s["ts"]))
    elif is_sctp:
        # SCTP: 按 TSN 排序，去除重复 TSN
        segments.sort(key=lambda s: (s["tsn"], s["ts"]))
    else:
        # UDP: 按时间戳排序
        segments.sort(key=lambda s: s["ts"])

    client_chunks: list[bytes] = []
    server_chunks: list[bytes] = []
    client_pkts = 0
    server_pkts = 0
    seen_seqs: set = set()
    seen_tsns: set = set()
    has_fin = False

    for seg in segments:
        if is_tcp:
            key = (seg["seq"], seg["len"], seg["is_client"])
            if key in seen_seqs:
                continue
            if seg["len"] == 0:
                if seg["flags"] & 0x01:
                    has_fin = True
                continue
            seen_seqs.add(key)
        elif is_sctp:
            # SCTP: 按 (tsn, is_client) 去重
            key = (seg["tsn"], seg["is_client"])
            if key in seen_tsns:
                continue
            if seg["len"] == 0:
                continue
            seen_tsns.add(key)
        else:
            if seg["len"] == 0:
                continue

        if seg["is_client"]:
            client_chunks.append(seg["payload"])
            client_pkts += 1
        else:
            server_chunks.append(seg["payload"])
            server_pkts += 1

    client_data = b"".join(client_chunks)[:max_bytes]
    server_data = b"".join(server_chunks)[:max_bytes]

    return {
        "client_data": client_data,
        "server_data": server_data,
        "client_packets": client_pkts,
        "server_packets": server_pkts,
        "client_raw": client_data.hex(),
        "server_raw": server_data.hex(),
        "total_bytes": len(client_data) + len(server_data),
        "stream_closed": has_fin,
    }


def _match_flow(
    raw: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    l4_proto: str,
) -> Optional[str]:
    """解析以太网帧，匹配 5-tuple（支持 IPv4/IPv6），返回报文摘要。"""
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

        if eth_type not in (0x0800, 0x86DD):  # IPv4 / IPv6 only
            return None

        version = (raw[ip_offset] >> 4) & 0x0F

        if version == 4:  # IPv4
            if len(raw) < ip_offset + 20:
                return None
            ihl = (raw[ip_offset] & 0x0F) * 4
            if ihl < 20:
                return None
            pkt_src = ".".join(str(raw[ip_offset + i]) for i in range(12, 16))
            pkt_dst = ".".join(str(raw[ip_offset + i]) for i in range(16, 20))
            proto = raw[ip_offset + 9]
            l4_offset = ip_offset + ihl

        elif version == 6:  # IPv6
            if len(raw) < ip_offset + 40:
                return None
            pkt_src = _ipv6_bytes_to_str(raw[ip_offset + 8:ip_offset + 24])
            pkt_dst = _ipv6_bytes_to_str(raw[ip_offset + 24:ip_offset + 40])
            proto = raw[ip_offset + 6]
            l4_offset = ip_offset + 40
            # 跳过 IPv6 扩展头
            while proto in (0, 43, 44, 60, 135):
                if l4_offset + 8 > len(raw):
                    return None
                if proto == 44:
                    proto = raw[l4_offset]
                    l4_offset += 8
                else:
                    ext_len = (raw[l4_offset + 1] + 1) * 8 if l4_offset + 1 < len(raw) else 0
                    proto = raw[l4_offset]
                    l4_offset += ext_len if ext_len > 0 else 8
                if l4_offset >= len(raw):
                    return None
        else:
            return None

        # 检查 IP 是否匹配（双向）
        ip_match = (pkt_src == src_ip and pkt_dst == dst_ip) or \
                   (pkt_src == dst_ip and pkt_dst == src_ip)
        if not ip_match:
            return None

        is_reverse = (pkt_src == dst_ip and pkt_dst == src_ip)
        l4_name = {6: "TCP", 17: "UDP", 132: "SCTP"}.get(proto, f"proto={proto}")

        if proto in (6, 17, 132):  # TCP / UDP / SCTP
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
            return f"{direction} {l4_name} len={len(raw)}"

        else:
            direction = "← 入" if is_reverse else "→ 出"
            return f"{direction} IP proto={proto} len={len(raw)}"

    except (IndexError, ValueError):
        pass

    return None
