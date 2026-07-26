"""数据包解析工具 — 纯 Python 实现，无外部依赖。

从原始字节解析 Ethernet/IP/TCP/UDP 头部，提取 5-tuple 信息。
用于 nDPI 不可用时的回退模式，也作为 nDPI 处理的前置步骤。
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from app.utils.logger import get_logger

logger = get_logger("collector.packet")


@dataclass
class ParsedPacket:
    """解析后的数据包信息。"""
    timestamp: datetime
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    l4_proto: str          # tcp / udp
    l7_proto: str          # 回退模式通过端口猜测
    payload: bytes
    ip_header_len: int
    total_len: int
    raw: bytes             # 原始包数据（留给 nDPI）
    interface: str = ""    # 抓包网卡名称


# ── 知名端口 → 协议映射 ────────────────────────────────

PORT_PROTO_MAP: dict[int, str] = {
    80: "http", 8080: "http", 8000: "http",
    443: "tls", 8443: "tls",
    53: "dns",
    22: "ssh",
    23: "telnet",
    25: "smtp", 587: "smtp", 465: "smtps",
    110: "pop3", 995: "pop3s",
    143: "imap", 993: "imaps",
    21: "ftp",
    69: "tftp",
    123: "ntp",
    161: "snmp", 162: "snmp",
    389: "ldap", 636: "ldaps",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    4433: "quic",
    51820: "wireguard",
    1194: "openvpn",
    5060: "sip", 5061: "sips",
    1935: "rtmp",
    554: "rtsp",
    1900: "upnp",
    5353: "mdns",
    67: "dhcp", 68: "dhcp",
}


def _guess_l7_proto(src_port: int, dst_port: int) -> str:
    """通过端口猜测应用层协议。"""
    # 先检查目标端口（服务端）
    if dst_port in PORT_PROTO_MAP:
        return PORT_PROTO_MAP[dst_port]
    # 再检查源端口（客户端）
    if src_port in PORT_PROTO_MAP:
        return PORT_PROTO_MAP[src_port]
    return "unknown"


def mac_bytes_to_str(mac: bytes) -> str:
    """将 6 字节 MAC 转为标准格式字符串。"""
    if len(mac) < 6:
        return ""
    return ":".join(f"{b:02x}" for b in mac)


def parse_ethernet(data: bytes) -> tuple[int, bytes, str, str]:
    """解析 Ethernet II 帧头，返回 (ethertype, payload, src_mac, dst_mac)。"""
    if len(data) < 14:
        return 0, b"", "", ""
    dst_mac = mac_bytes_to_str(data[0:6])
    src_mac = mac_bytes_to_str(data[6:12])
    ethertype = struct.unpack("!H", data[12:14])[0]
    return ethertype, data[14:], src_mac, dst_mac


def parse_ipv4(data: bytes) -> Optional[dict]:
    """解析 IPv4 头部，返回字段字典。"""
    if len(data) < 20:
        return None
    version_ihl = data[0]
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack("!H", data[2:4])[0]
    protocol = data[9]
    src_ip = str(ipaddress.IPv4Address(data[12:16]))
    dst_ip = str(ipaddress.IPv4Address(data[16:20]))
    return {
        "version": 4,
        "ihl": ihl,
        "total_len": total_len,
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload": data[ihl:],
    }


def parse_ipv6(data: bytes) -> Optional[dict]:
    """解析 IPv6 头部（固定 40 字节），返回字段字典。

    IPv6 头格式:
      Version(4) + Traffic Class(8) + Flow Label(20)
      Payload Length(16) + Next Header(8) + Hop Limit(8)
      Source Address(128) + Destination Address(128)
    """
    if len(data) < 40:
        return None
    # 验证版本号 (前 4 bits)
    if (data[0] >> 4) != 6:
        return None
    payload_len = struct.unpack("!H", data[4:6])[0]
    next_header = data[6]
    src_ip = str(ipaddress.IPv6Address(data[8:24]))
    dst_ip = str(ipaddress.IPv6Address(data[24:40]))
    total_len = 40 + payload_len
    # 处理扩展头（逐跳、路由、分片、ESP、AH 等），找到真正的 L4 协议
    l4_proto = next_header
    l4_offset = 40
    # 常见扩展头需要跳过
    while l4_proto in (0, 43, 44, 60, 135):  # Hop-by-Hop, Routing, Fragment, Dest-Opts, Mobility
        if l4_offset + 8 > len(data):
            break
        if l4_proto == 44:  # Fragment header 固定 8 字节
            l4_proto = data[l4_offset]
            l4_offset += 8
        else:
            ext_len = (data[l4_offset + 1] + 1) * 8 if l4_offset + 1 < len(data) else 0
            l4_proto = data[l4_offset]
            l4_offset += ext_len if ext_len > 0 else 8
        if l4_offset >= len(data):
            break
    return {
        "version": 6,
        "total_len": total_len,
        "protocol": l4_proto,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "payload": data[l4_offset:],
    }


def parse_tcp(data: bytes) -> Optional[dict]:
    """解析 TCP 头部。"""
    if len(data) < 20:
        return None
    src_port = struct.unpack("!H", data[0:2])[0]
    dst_port = struct.unpack("!H", data[2:4])[0]
    data_offset = (data[12] >> 4) * 4
    if data_offset < 20 or len(data) < data_offset:
        return None
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "header_len": data_offset,
        "payload": data[data_offset:],
    }


def parse_udp(data: bytes) -> Optional[dict]:
    """解析 UDP 头部。"""
    if len(data) < 8:
        return None
    src_port = struct.unpack("!H", data[0:2])[0]
    dst_port = struct.unpack("!H", data[2:4])[0]
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "payload": data[8:],
    }


L4_PROTO_MAP = {1: "icmp", 6: "tcp", 17: "udp", 132: "sctp"}


def parse_packet(raw_packet: bytes, ts: Optional[float] = None) -> Optional[ParsedPacket]:
    """从原始二层数据包解析出 ParsedPacket。

    Args:
        raw_packet: 完整的二层（Ethernet）数据包。
        ts: 时间戳（秒），默认为当前时间。

    Returns:
        解析后的 ParsedPacket，非 IP 包返回 None。
    """
    if ts is None:
        ts = datetime.now(timezone.utc).timestamp()
    timestamp = datetime.fromtimestamp(ts, tz=timezone.utc)

    # 解析 Ethernet 帧
    ethertype, eth_payload, src_mac, dst_mac = parse_ethernet(raw_packet)

    # 解析 IPv4 或 IPv6
    if ethertype == 0x0800:
        ip_info = parse_ipv4(eth_payload)
    elif ethertype == 0x86DD:
        ip_info = parse_ipv6(eth_payload)
    else:
        logger.debug("跳过非 IP 包: ethertype=0x%04x", ethertype)
        return None
    if ip_info is None:
        return None

    l4_proto_str = L4_PROTO_MAP.get(ip_info["protocol"], "unknown")
    l4_payload = ip_info["payload"]

    src_port = 0
    dst_port = 0
    l7_payload = b""

    if l4_proto_str == "tcp":
        tcp_info = parse_tcp(l4_payload)
        if tcp_info:
            src_port = tcp_info["src_port"]
            dst_port = tcp_info["dst_port"]
            l7_payload = tcp_info["payload"]
    elif l4_proto_str == "udp":
        udp_info = parse_udp(l4_payload)
        if udp_info:
            src_port = udp_info["src_port"]
            dst_port = udp_info["dst_port"]
            l7_payload = udp_info["payload"]

    l7_proto = _guess_l7_proto(src_port, dst_port)

    # IPv4 的 ihl 在头部中编码，IPv6 固定 40 字节
    ip_hdr_len = ip_info.get("ihl", 40) if ip_info.get("version") == 4 else 40

    return ParsedPacket(
        timestamp=timestamp,
        src_mac=src_mac,
        dst_mac=dst_mac,
        src_ip=ip_info["src_ip"],
        dst_ip=ip_info["dst_ip"],
        src_port=src_port,
        dst_port=dst_port,
        l4_proto=l4_proto_str,
        l7_proto=l7_proto,
        payload=l7_payload,
        ip_header_len=ip_hdr_len,
        total_len=ip_info["total_len"],
        raw=raw_packet,
    )


# ── L7 元数据提取 ──────────────────────────────────────

# 明文内容最大提取长度
_MAX_PLAINTEXT_BYTES = 2048


def extract_plaintext_content(payload: bytes, max_bytes: int = _MAX_PLAINTEXT_BYTES) -> str:
    """提取明文协议的全部请求/响应内容。

    检测 payload 是否可打印文本，若是则返回完整内容（截断至 max_bytes）。
    二进制内容返回空字符串。
    """
    if not payload:
        return ""
    length = min(len(payload), max_bytes)
    sample = payload[:length]

    # 可打印 ASCII / UTF-8 文本检测：至少 70% 字节可打印（放宽以包含含少量二进制干扰的文本）
    printable = sum(1 for b in sample if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    if len(sample) > 0 and printable / len(sample) < 0.70:
        return ""

    text = sample.decode("utf-8", errors="replace")
    # 替换控制字符（保留 \\t \\n \\r）为空格
    cleaned = "".join(c if c >= " " or c in "\t\n\r" else " " for c in text)
    return cleaned


def extract_dns_query(payload: bytes) -> str:
    """从 DNS 查询包中提取域名。

    Args:
        payload: UDP payload（DNS 消息）。

    Returns:
        查询的域名，如 "example.com"，无法解析返回空字符串。
    """
    if len(payload) < 12:
        return ""
    # DNS header: id(2) + flags(2) + qdcount(2) + ancount(2) + nscount(2) + arcount(2)
    # 检查是否为标准查询 (QR=0, OPCODE=0)
    flags = struct.unpack("!H", payload[2:4])[0]
    qr = (flags >> 15) & 1
    if qr != 0:  # 不是查询（可能是响应）
        return ""
    opcode = (flags >> 11) & 0x0F
    if opcode != 0:
        return ""

    # 问题数
    qdcount = struct.unpack("!H", payload[4:6])[0]
    if qdcount == 0:
        return ""

    # 解析 QNAME（域名）
    pos = 12
    labels: list[bytes] = []
    while pos < len(payload):
        length = payload[pos]
        if length == 0:
            break
        if length & 0xC0:  # 压缩指针
            break
        pos += 1
        if pos + length > len(payload):
            break
        labels.append(payload[pos:pos + length])
        pos += length

    if not labels:
        return ""
    return ".".join(label.decode("utf-8", errors="replace") for label in labels)


def extract_host(payload: bytes, l7_proto: str) -> str:
    """从 HTTP 请求、DNS 查询、TLS SNI 或 SOCKS CONNECT 中提取目标主机/域名。"""
    if l7_proto == "http":
        # 从 HTTP 请求中找 Host 头
        text = payload.decode("utf-8", errors="replace")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line[5:].strip()
        return ""
    if l7_proto == "dns":
        return extract_dns_query(payload)
    if l7_proto in ("tls", "ssl"):
        # 尝试提取 TLS SNI（Server Name Indication）
        try:
            # 简单 SNI 提取：ClientHello 中查找 server_name 扩展
            if len(payload) < 50:
                return ""
            if payload[0] not in (0x16,):
                return ""
            pos = 5 + 4 + 2 + 32
            if pos >= len(payload):
                return ""
            session_len = payload[pos]
            pos += 1 + session_len
            if pos + 2 > len(payload):
                return ""
            cipher_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2 + cipher_len
            if pos >= len(payload):
                return ""
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                return ""
            ext_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2
            end = pos + ext_len
            while pos + 4 <= end:
                ext_type = (payload[pos] << 8) | payload[pos + 1]
                ext_data_len = (payload[pos + 2] << 8) | payload[pos + 3]
                pos += 4
                if ext_type == 0:
                    if pos + 6 <= end:
                        # ServerNameList: sni_list_len(2) + name_type(1) + name_len(2) + name_data
                        sni_len_val = (payload[pos + 3] << 8) | payload[pos + 4]
                        sni_start = pos + 5
                        if sni_start + sni_len_val <= end:
                            return payload[sni_start:sni_start + sni_len_val].decode("utf-8", errors="replace")
                pos += ext_data_len
        except Exception:
            pass
        return ""
    # 通用检测：SOCKS CONNECT、HTTP 请求行等
    try:
        text = payload.decode("utf-8", errors="replace")
        # SOCKS CONNECT host:port HTTP/1.1
        if text.startswith("CONNECT "):
            rest = text[8:]
            host_part = rest.split(" ")[0]
            if ":" in host_part:
                host = host_part.rsplit(":", 1)[0]
                return host.strip()
            return host_part.strip()
        # HTTP 请求行 GET/POST/PUT http://host/path
        if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ")):
            # 可能是 HTTP 代理请求
            first_line = text.split("\r\n")[0]
            parts = first_line.split(" ")
            if len(parts) >= 2:
                url = parts[1]
                if url.startswith("http://") or url.startswith("https://"):
                    from urllib.parse import urlparse
                    try:
                        parsed = urlparse(url)
                        if parsed.hostname:
                            return parsed.hostname
                    except Exception:
                        pass
                # 也可能是 CONNECT 风格的 HTTP 请求
                if "://" not in url and ":" in url:
                    host = url.rsplit(":", 1)[0]
                    return host.strip()
    except Exception:
        pass
    return ""


def extract_first_line(payload: bytes) -> str:
    """提取文本协议的第一行（遇到 \\r\\n 或 \\n 截断）。

    过滤掉二进制乱码（只保留可打印 ASCII / UTF-8 文本）。
    """
    if not payload:
        return ""
    end = payload.find(b"\r\n")
    if end < 0:
        end = payload.find(b"\n")
    if end < 0:
        end = min(len(payload), 256)
    line = payload[:end]

    # 过滤二进制：至少 80% 字节是可打印 ASCII
    printable = sum(1 for b in line if 0x20 <= b < 0x7F)
    if len(line) > 0 and printable / len(line) < 0.8:
        return ""

    return line.decode("utf-8", errors="replace")


def extract_http_request(payload: bytes) -> str:
    """从 HTTP 请求中提取方法 + URL。"""
    line = extract_first_line(payload)
    if not line:
        return ""
    methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ",
               "OPTIONS ", "CONNECT ", "TRACE ")
    if not any(line.startswith(m) for m in methods):
        return ""
    return line


def extract_ftp(payload: bytes) -> str:
    """从 FTP 命令中提取关键操作。"""
    line = extract_first_line(payload)
    if not line:
        return ""
    upper = line.upper()
    cmds = ("USER ", "PASS ", "CWD ", "LIST", "RETR ", "STOR ", "DELE ",
            "MKD ", "RMD ", "RNFR ", "RNTO ", "PWD", "SYST", "QUIT")
    if not any(upper.startswith(c) for c in cmds):
        return ""
    return f"FTP {line.strip()}"


def extract_smtp(payload: bytes) -> str:
    """从 SMTP 中提取发件人/收件人。"""
    line = extract_first_line(payload)
    if not line:
        return ""
    upper = line.upper()
    # 客户端命令
    if upper.startswith("EHLO ") or upper.startswith("HELO "):
        return f"SMTP {line.strip()}"
    if upper.startswith("MAIL FROM:"):
        return f"SMTP {line.strip()}"
    if upper.startswith("RCPT TO:"):
        return f"SMTP {line.strip()}"
    # 服务端响应
    if line[0].isdigit() and len(line) >= 3 and line[3:4] in (" ", "-"):
        domain_pos = line.find(" ")
        if domain_pos > 0:
            return f"SMTP {line[:domain_pos]} {line[domain_pos+1:50]}"
    return ""


def extract_pop3(payload: bytes) -> str:
    """从 POP3 中提取命令。"""
    line = extract_first_line(payload)
    if not line:
        return ""
    upper = line.upper()
    cmds = ("USER ", "PASS ", "STAT", "LIST", "RETR ", "DELE ", "QUIT")
    if any(upper.startswith(c) for c in cmds):
        return f"POP3 {line.strip()}"
    return ""


def extract_redis(payload: bytes) -> str:
    """从 Redis 协议中提取命令。"""
    # Redis 使用 RESP 协议: *3\\r\\n$3\\r\\nSET\\r\\n$3\\r\\nkey\\r\\n...
    # 或 inline 命令: SET key value\\r\\n
    if not payload:
        return ""
    # 尝试 inline 命令
    line = extract_first_line(payload)
    if line and not line.startswith("*") and not line.startswith("$") and not line.startswith("+"):
        upper = line.upper()
        cmds = ("SET ", "GET ", "DEL ", "HSET ", "HGET ", "LPUSH ", "RPUSH ",
                "SADD ", "ZADD ", "EXPIRE ", "PUBLISH ", "SUBSCRIBE", "PING")
        if any(upper.startswith(c) for c in cmds):
            return f"Redis {line.strip()}"
    return ""


def extract_sip(payload: bytes) -> str:
    """从 SIP 信令中提取方法 + URI。"""
    line = extract_first_line(payload)
    if not line:
        return ""
    methods = ("INVITE ", "ACK ", "BYE ", "CANCEL ", "REGISTER ", "OPTIONS ",
               "INFO ", "NOTIFY ", "MESSAGE ", "SUBSCRIBE ", "REFER ", "UPDATE ")
    if any(line.upper().startswith(m) for m in methods):
        return f"SIP {line.strip()}"
    # 响应行: SIP/2.0 200 OK
    if line.startswith("SIP/2.0"):
        return f"SIP {line.strip()}"
    return ""
