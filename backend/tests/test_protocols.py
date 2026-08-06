"""协议捕获与解析测试套件 — 一个协议一个测试类。

验证每种协议：
  1. 能被 parse_packet 正确解析（正确的 l4/l7 协议 + 五元组）
  2. 能提取出正确的元数据（host / DNS 域名 / SNI / 内容等）
  3. 通过 pcap 回放能真正"捕获"并写入存储（集成测试）

协议覆盖：HTTP / TLS / DNS / SOCKS5 / NTP / SSH / DHCP / QUIC /
         SMTP / MySQL / Redis / MongoDB / FTP / SNMP / LDAP /
         WireGuard / OpenVPN / SIP / RTMP / RTSP / mDNS / IPv6 /
         TCP/UDP/SCTP L4 / VLAN / PPPoE 等。

纯端口回退 + 内容解析，不依赖 nDPI，保证测试确定性。
"""

from __future__ import annotations

import asyncio
import socket
import struct
from datetime import datetime, timezone

import pytest

from app.collector.packet import (
    ParsedPacket,
    extract_dns_query,
    extract_host,
    extract_http_request,
    parse_dns_payload,
    parse_packet,
)


# ══════════════════════════════════════════════════════════════
# 数据包构建器（Ethernet / IPv4 / IPv6 / TCP / UDP + 协议载荷）
# ══════════════════════════════════════════════════════════════

def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def build_eth(
    payload: bytes,
    eth_type: int = 0x0800,
    src_mac: str = "00:11:22:33:44:55",
    dst_mac: str = "66:77:88:99:aa:bb",
) -> bytes:
    """构建 Ethernet II 帧。"""
    return _mac_bytes(dst_mac) + _mac_bytes(src_mac) + struct.pack("!H", eth_type) + payload


def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    """构建 IPv4 头 + 载荷（不含 Ethernet）。"""
    total_len = 20 + len(payload)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, 0, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + payload


def build_ipv6(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    """构建 IPv6 头 + 载荷（不含 Ethernet，无扩展头）。"""
    ver_tc_flow = 6 << 28
    return (
        struct.pack("!IHBB", ver_tc_flow, len(payload), next_header, 64)
        + socket.inet_pton(socket.AF_INET6, src)
        + socket.inet_pton(socket.AF_INET6, dst)
        + payload
    )


def build_tcp(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> bytes:
    """构建 TCP 头（20 字节）+ 载荷。flags 默认 PSH|ACK。"""
    return (
        struct.pack("!HHIIBBHHH", sport, dport, 1, 1, (5 << 4), flags, 65535, 0, 0)
        + payload
    )


def build_udp(sport: int, dport: int, payload: bytes) -> bytes:
    """构建 UDP 头 + 载荷。"""
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def build_sctp(sport: int, dport: int, payload: bytes) -> bytes:
    """构建 SCTP 头（12 字节）+ 载荷。"""
    return struct.pack("!HHII", sport, dport, 0, 0) + payload


def build_tcp_packet(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    payload: bytes,
    flags: int = 0x18,
    eth_type: int = 0x0800,
) -> bytes:
    """完整 Ethernet+IPv4+TCP 数据包。"""
    return build_eth(build_ipv4(src, dst, 6, build_tcp(sport, dport, payload, flags)), eth_type)


def build_udp_packet(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    """完整 Ethernet+IPv4+UDP 数据包。"""
    return build_eth(build_ipv4(src, dst, 17, build_udp(sport, dport, payload)))


def build_ipv6_tcp_packet(
    src: str, dst: str, sport: int, dport: int, payload: bytes
) -> bytes:
    """完整 Ethernet+IPv6+TCP 数据包。"""
    return build_eth(build_ipv6(src, dst, 6, build_tcp(sport, dport, payload)), 0x86DD)


def build_ipv6_udp_packet(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    """完整 Ethernet+IPv6+UDP 数据包。"""
    return build_eth(build_ipv6(src, dst, 17, build_udp(sport, dport, payload)), 0x86DD)


# ── 协议载荷构建器 ─────────────────────────────────────

def build_http_get(host: str = "www.example.com", path: str = "/index.html") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n".encode()
        + f"Host: {host}\r\n".encode()
        + b"User-Agent: pytest/1.0\r\nAccept: */*\r\n\r\n"
    )


def build_tls_clienthello(sni: str = "www.example.com") -> bytes:
    """构建 TLS 1.3 ClientHello（含 SNI 扩展）。"""
    sni_bytes = sni.encode()
    # name_type(1B) + name_len(2B) + name，符合 TLS SNI 规范
    server_name = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(server_name)) + server_name  # ServerNameList
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list  # type=SNI

    cipher = struct.pack("!H", 0x1301)  # TLS_AES_128_GCM_SHA256
    body = (
        struct.pack("!H", 0x0303)        # client_version = TLS 1.2
        + b"\x00" * 32                   # random
        + b"\x00"                        # session_id_len = 0
        + struct.pack("!H", len(cipher)) # cipher_suites_len
        + cipher
        + b"\x01\x00"                    # compression_methods_len + method
        + struct.pack("!H", len(sni_ext)) + sni_ext  # extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body  # ClientHello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake  # TLS record


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def build_dns_query(name: str = "www.example.com", qtype: int = 1, qid: int = 0x1234) -> bytes:
    """构建标准 DNS 查询（A 记录）。"""
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    question = _dns_name(name) + struct.pack("!HH", qtype, 1)
    return header + question


def build_dns_response(
    name: str = "www.example.com",
    rdata_ip: str = "93.184.216.34",
    qid: int = 0x1234,
    answer_type: int = 1,
    rdata: bytes | None = None,
) -> bytes:
    """构建 DNS 响应（QR=1, 含 1 个答案）。"""
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    question = _dns_name(name) + struct.pack("!HH", 1, 1)
    if rdata is None:
        if answer_type == 1:
            rdata = socket.inet_aton(rdata_ip)
        elif answer_type == 28:
            rdata = socket.inet_pton(socket.AF_INET6, rdata_ip)
        elif answer_type == 2:  # NS → 指向另一个域名
            rdata = _dns_name("ns1.example.com")
        elif answer_type == 16:  # TXT
            txt = b"v=spf1 include:_spf.example.com ~all"
            rdata = bytes([len(txt)]) + txt
        elif answer_type == 15:  # MX
            rdata = struct.pack("!H", 10) + _dns_name("mail.example.com")
        else:
            rdata = b"\x00"
    answer = (
        b"\xc0\x0c"                       # 名称压缩指针 → 问题区
        + struct.pack("!HHIH", answer_type, 1, 300, len(rdata))
        + rdata
    )
    return header + question + answer


def build_socks5_connect(host: str = "proxy.example.com", port: int = 443) -> bytes:
    """SOCKS5 CONNECT 请求（域名型）。"""
    h = host.encode()
    return b"\x05\x01\x00" + b"\x03" + bytes([len(h)]) + h + struct.pack("!H", port)


def build_socks5_connect_ipv4(ip: str = "203.0.113.7", port: int = 443) -> bytes:
    """SOCKS5 CONNECT 请求（IPv4 型）。"""
    return b"\x05\x01\x00" + b"\x01" + socket.inet_aton(ip) + struct.pack("!H", port)


def build_ntp_packet() -> bytes:
    """NTP 客户端请求包（48 字节）。"""
    return b"\x1b" + b"\x00" * 47


def build_ssh_banner() -> bytes:
    return b"SSH-2.0-OpenSSH_9.0\r\n"


def build_dhcp_discover() -> bytes:
    """DHCP DISCOVER（BOOTP 头 + magic cookie）。"""
    bootp = struct.pack("!BBBBIHH", 1, 1, 6, 0, 0x12345678, 0, 0)
    bootp += b"\x00" * 12  # ciaddr(4)+yiaddr(4)+siaddr(4)
    bootp += b"\x00" * 4   # giaddr
    bootp += _mac_bytes("00:11:22:33:44:55") + b"\x00" * 10  # chaddr
    bootp += b"\x00" * 64 + b"\x00" * 128  # sname + file
    bootp += b"\x63\x82\x53\x63"           # DHCP magic cookie
    bootp += struct.pack("!HBB", 53, 1, 1)  # option 53 = DHCPDISCOVER
    bootp += b"\xff"                        # end
    return bootp


def build_quic_initial() -> bytes:
    """QUIC v1 Initial 包（长头）。"""
    return b"\xc3" + b"\x00" * 20


# ── pcap 文件写入器 ───────────────────────────────────

def write_pcap(path: str, packets: list[bytes], ts_sec_base: int = 1600000000, ts_step: float = 0.1) -> None:
    """将原始包列表写成小端 pcap 文件。

    每个包按 ts_sec_base + i*ts_step 递增时间戳。
    """
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))  # linktype=1 Ethernet
        for i, pkt in enumerate(packets):
            ts = ts_sec_base + i * ts_step
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)))
            f.write(pkt)


# ══════════════════════════════════════════════════════════════
# HTTP 协议
# ══════════════════════════════════════════════════════════════

class TestHTTPProtocol:
    """HTTP 协议：TCP 80 端口识别 + Host 提取 + 请求行提取。"""

    def test_parse_http_get(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 80, build_http_get()))
        assert pkt is not None
        assert pkt.l4_proto == "tcp"
        assert pkt.l7_proto == "http"
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "93.184.216.34"
        assert pkt.src_port == 40000
        assert pkt.dst_port == 80
        assert pkt.src_mac == "00:11:22:33:44:55"
        assert pkt.dst_mac == "66:77:88:99:aa:bb"

    def test_parse_http_8080(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 8080, build_http_get()))
        assert pkt is not None and pkt.l7_proto == "http"

    def test_extract_host(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 80, build_http_get("www.baidu.com")))
        assert pkt is not None
        host = extract_host(pkt.payload, "http")
        assert host == "www.baidu.com"

    def test_extract_http_request(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 80, build_http_get()))
        assert pkt is not None
        assert extract_http_request(pkt.payload) == "GET /index.html HTTP/1.1"

    def test_http_response_payload(self):
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"
        pkt = parse_packet(build_tcp_packet("93.184.216.34", "10.0.0.1", 80, 40000, resp))
        assert pkt is not None
        assert pkt.l7_proto == "http"
        assert pkt.payload.startswith(b"HTTP/1.1 200 OK")

    def test_http_via_8000_port(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 8000, build_http_get()))
        assert pkt is not None and pkt.l7_proto == "http"


# ══════════════════════════════════════════════════════════════
# TLS 协议
# ══════════════════════════════════════════════════════════════

class TestTLSProtocol:
    """TLS 协议：TCP 443 识别 + SNI 提取。"""

    def test_parse_tls(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 443, build_tls_clienthello("www.github.com")))
        assert pkt is not None
        assert pkt.l7_proto == "tls"
        assert pkt.l4_proto == "tcp"

    def test_parse_tls_8443(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 8443, build_tls_clienthello()))
        assert pkt is not None and pkt.l7_proto == "tls"

    def test_extract_sni(self):
        payload = build_tls_clienthello("api.example.com")
        sni = extract_host(payload, "tls")
        assert sni == "api.example.com"

    def test_extract_sni_ssl_alias(self):
        payload = build_tls_clienthello("secure.example.org")
        sni = extract_host(payload, "ssl")
        assert sni == "secure.example.org"

    def test_extract_sni_long_domain(self):
        payload = build_tls_clienthello("a.very.long.subdomain.example.com")
        assert extract_host(payload, "tls") == "a.very.long.subdomain.example.com"


# ══════════════════════════════════════════════════════════════
# DNS 协议
# ══════════════════════════════════════════════════════════════

class TestDNSProtocol:
    """DNS 协议：UDP 53 识别 + 域名提取 + 深度解析（问题/答案）。"""

    def test_parse_dns_query(self):
        pkt = parse_packet(build_udp_packet("10.0.0.1", "8.8.8.8", 40000, 53, build_dns_query("www.baidu.com")))
        assert pkt is not None
        assert pkt.l7_proto == "dns"
        assert pkt.l4_proto == "udp"
        assert pkt.dst_port == 53

    def test_parse_dns_response(self):
        pkt = parse_packet(build_udp_packet("8.8.8.8", "10.0.0.1", 53, 40000, build_dns_response("www.baidu.com")))
        assert pkt is not None and pkt.l7_proto == "dns"

    def test_extract_dns_query_domain(self):
        pkt = parse_packet(build_udp_packet("10.0.0.1", "8.8.8.8", 40000, 53, build_dns_query("www.google.com")))
        assert pkt is not None
        assert extract_dns_query(pkt.payload) == "www.google.com"

    def test_extract_host_dns(self):
        pkt = parse_packet(build_udp_packet("10.0.0.1", "8.8.8.8", 40000, 53, build_dns_query("api.github.com")))
        assert pkt is not None
        assert extract_host(pkt.payload, "dns") == "api.github.com"

    def test_parse_dns_question(self):
        info = parse_dns_payload(build_dns_query("www.example.com"))
        assert info["is_response"] is False
        assert info["questions"] == [{"name": "www.example.com", "qtype": "A"}]
        assert info["answers"] == []

    def test_parse_dns_response_a(self):
        info = parse_dns_payload(build_dns_response("www.example.com", "93.184.216.34"))
        assert info["is_response"] is True
        assert info["questions"][0]["name"] == "www.example.com"
        assert info["answers"][0]["type"] == "A"
        assert info["answers"][0]["data"] == "93.184.216.34"
        assert info["answers"][0]["ttl"] == 300

    def test_parse_dns_response_aaaa(self):
        info = parse_dns_payload(build_dns_response("ipv6.example.com", "2606:2800:220:1:248:1893:25c8:1946", answer_type=28))
        assert info["answers"][0]["type"] == "AAAA"
        assert info["answers"][0]["data"] == "2606:2800:220:1:248:1893:25c8:1946"

    def test_parse_dns_response_ns(self):
        info = parse_dns_payload(build_dns_response("example.com", answer_type=2))
        assert info["answers"][0]["type"] == "NS"
        assert info["answers"][0]["data"] == "ns1.example.com"

    def test_parse_dns_response_txt(self):
        info = parse_dns_payload(build_dns_response("example.com", answer_type=16))
        assert info["answers"][0]["type"] == "TXT"
        assert "spf1" in info["answers"][0]["data"]

    def test_parse_dns_response_mx(self):
        info = parse_dns_payload(build_dns_response("example.com", answer_type=15))
        assert info["answers"][0]["type"] == "MX"
        assert info["answers"][0]["data"] == "10 mail.example.com"

    def test_parse_dns_compression_pointer(self):
        """响应中的答案名称使用压缩指针 0xC00C 指向问题区。"""
        info = parse_dns_payload(build_dns_response("cdn.example.com", "1.2.3.4"))
        assert info["answers"][0]["name"] == "cdn.example.com"

    def test_parse_dns_empty_payload(self):
        assert parse_dns_payload(b"") == {}
        assert parse_dns_payload(b"\x00" * 5) == {}

    def test_dns_multiple_questions(self):
        """多问题查询（如 ANY + A）。"""
        header = struct.pack("!HHHHHH", 0x0001, 0x0100, 2, 0, 0, 0)
        q = _dns_name("a.example.com") + struct.pack("!HH", 1, 1)
        q += _dns_name("a.example.com") + struct.pack("!HH", 28, 1)
        info = parse_dns_payload(header + q)
        assert len(info["questions"]) == 2
        assert info["questions"][1]["qtype"] == "AAAA"


# ══════════════════════════════════════════════════════════════
# SOCKS5 协议
# ══════════════════════════════════════════════════════════════

class TestSOCKS5Protocol:
    """SOCKS5 协议：从 CONNECT 请求提取目标（域名 / IPv4）。"""

    def test_extract_socks5_domain(self):
        payload = build_socks5_connect("socks-target.example.com")
        assert extract_host(payload, "socks") == "socks-target.example.com"

    def test_extract_socks5_domain_via_unknown(self):
        """端口回退模式下 l7_proto=unknown 也应能提取 SOCKS 目标。"""
        payload = build_socks5_connect("proxy-target.org")
        assert extract_host(payload, "unknown") == "proxy-target.org"

    def test_extract_socks5_ipv4(self):
        payload = build_socks5_connect_ipv4("203.0.113.7")
        assert extract_host(payload, "socks5") == "203.0.113.7"

    def test_socks5_short_payload_no_crash(self):
        assert extract_host(b"\x05\x01", "socks") == ""


# ══════════════════════════════════════════════════════════════
# NTP 协议
# ══════════════════════════════════════════════════════════════

class TestNTPProtocol:
    """NTP 协议：UDP 123 识别。"""

    def test_parse_ntp(self):
        pkt = parse_packet(build_udp_packet("10.0.0.1", "185.125.190.57", 40000, 123, build_ntp_packet()))
        assert pkt is not None
        assert pkt.l7_proto == "ntp"
        assert pkt.l4_proto == "udp"
        assert len(pkt.payload) == 48

    def test_ntp_response(self):
        pkt = parse_packet(build_udp_packet("185.125.190.57", "10.0.0.1", 123, 40000, build_ntp_packet()))
        assert pkt is not None and pkt.l7_proto == "ntp"


# ══════════════════════════════════════════════════════════════
# SSH 协议
# ══════════════════════════════════════════════════════════════

class TestSSHProtocol:
    """SSH 协议：TCP 22 识别。"""

    def test_parse_ssh(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "203.0.113.9", 40000, 22, build_ssh_banner()))
        assert pkt is not None
        assert pkt.l7_proto == "ssh"
        assert pkt.l4_proto == "tcp"

    def test_ssh_banner_payload(self):
        pkt = parse_packet(build_tcp_packet("203.0.113.9", "10.0.0.1", 22, 40000, build_ssh_banner()))
        assert pkt is not None
        assert pkt.payload.startswith(b"SSH-2.0-")


# ══════════════════════════════════════════════════════════════
# DHCP 协议
# ══════════════════════════════════════════════════════════════

class TestDHCPProtocol:
    """DHCP 协议：UDP 67/68 识别。"""

    def test_parse_dhcp_discover(self):
        pkt = parse_packet(build_udp_packet("0.0.0.0", "255.255.255.255", 68, 67, build_dhcp_discover()))
        assert pkt is not None
        assert pkt.l7_proto == "dhcp"
        assert pkt.l4_proto == "udp"

    def test_dhcp_offer_from_server(self):
        pkt = parse_packet(build_udp_packet("192.168.1.1", "255.255.255.255", 67, 68, build_dhcp_discover()))
        assert pkt is not None and pkt.l7_proto == "dhcp"


# ══════════════════════════════════════════════════════════════
# QUIC 协议
# ══════════════════════════════════════════════════════════════

class TestQUICProtocol:
    """QUIC 协议：UDP 4433 识别。"""

    def test_parse_quic_4433(self):
        pkt = parse_packet(build_udp_packet("10.0.0.1", "8.8.8.8", 40000, 4433, build_quic_initial()))
        assert pkt is not None
        assert pkt.l7_proto == "quic"
        assert pkt.l4_proto == "udp"


# ══════════════════════════════════════════════════════════════
# 其它端口协议（参数化，一次测一批）
# ══════════════════════════════════════════════════════════════

class TestPortBasedProtocols:
    """端口回退模式下的协议识别（参数化）。"""

    @pytest.mark.parametrize(
        "port,proto,l4",
        [
            (21, "ftp", "tcp"),
            (25, "smtp", "tcp"),
            (587, "smtp", "tcp"),
            (110, "pop3", "tcp"),
            (143, "imap", "tcp"),
            (161, "snmp", "udp"),
            (162, "snmp", "udp"),
            (389, "ldap", "tcp"),
            (3306, "mysql", "tcp"),
            (5432, "postgresql", "tcp"),
            (6379, "redis", "tcp"),
            (27017, "mongodb", "tcp"),
            (51820, "wireguard", "udp"),
            (1194, "openvpn", "udp"),
            (5060, "sip", "udp"),
            (1935, "rtmp", "tcp"),
            (554, "rtsp", "tcp"),
            (1900, "upnp", "udp"),
            (5353, "mdns", "udp"),
        ],
    )
    def test_tcp_udp_port_detection(self, port, proto, l4):
        if l4 == "tcp":
            pkt = parse_packet(build_tcp_packet("10.0.0.1", "203.0.113.9", 40000, port, b"\x00\x01\x02\x03"))
        else:
            pkt = parse_packet(build_udp_packet("10.0.0.1", "203.0.113.9", 40000, port, b"\x00\x01\x02\x03"))
        assert pkt is not None
        assert pkt.l4_proto == l4
        assert pkt.l7_proto == proto, f"port {port} 应识别为 {proto}"

    def test_unknown_port(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "203.0.113.9", 40000, 9999, b"hello"))
        assert pkt is not None
        assert pkt.l7_proto == "unknown"


# ══════════════════════════════════════════════════════════════
# IPv6 协议
# ══════════════════════════════════════════════════════════════

class TestIPv6Protocol:
    """IPv6：TCP/UDP 载荷解析 + 地址提取。"""

    def test_ipv6_tcp_http(self):
        pkt = parse_packet(build_ipv6_tcp_packet(
            "2001:db8::1", "2606:2800:220:1:248:1893:25c8:1946", 40000, 80, build_http_get("ipv6.example.com")
        ))
        assert pkt is not None
        assert pkt.src_ip == "2001:db8::1"
        assert pkt.dst_ip == "2606:2800:220:1:248:1893:25c8:1946"
        assert pkt.l4_proto == "tcp"
        assert pkt.l7_proto == "http"
        assert pkt.src_port == 40000
        assert pkt.dst_port == 80

    def test_ipv6_udp_dns(self):
        pkt = parse_packet(build_ipv6_udp_packet(
            "2001:db8::1", "2001:4860:4860::8888", 40000, 53, build_dns_query("v6.example.com")
        ))
        assert pkt is not None
        assert pkt.l4_proto == "udp"
        assert pkt.l7_proto == "dns"
        assert extract_dns_query(pkt.payload) == "v6.example.com"

    def test_ipv6_tls_sni(self):
        pkt = parse_packet(build_ipv6_tcp_packet(
            "2001:db8::1", "2606:4700:4700::1111", 40000, 443, build_tls_clienthello("cloudflare.example.com")
        ))
        assert pkt is not None and pkt.l7_proto == "tls"
        assert extract_host(pkt.payload, "tls") == "cloudflare.example.com"


# ══════════════════════════════════════════════════════════════
# L4 传输层协议
# ══════════════════════════════════════════════════════════════

class TestL4Protocols:
    """TCP / UDP / SCTP / ICMP 传输层识别。"""

    def test_tcp_without_payload(self):
        raw = build_eth(build_ipv4("10.0.0.1", "203.0.113.9", 6, build_tcp(40000, 443, b"", flags=0x02)))
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l4_proto == "tcp"
        assert pkt.l7_proto == "tls"
        assert pkt.payload == b""

    def test_udp_without_payload(self):
        raw = build_eth(build_ipv4("10.0.0.1", "8.8.8.8", 17, build_udp(40000, 53, b"")))
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l4_proto == "udp"
        assert pkt.l7_proto == "dns"

    def test_sctp_protocol_identification(self):
        """SCTP (proto 132) 应识别为 sctp（端口不解析）。"""
        raw = build_eth(build_ipv4("10.0.0.1", "203.0.113.9", 132, build_sctp(40000, 3868, b"\x00" * 12)))
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l4_proto == "sctp"
        assert pkt.src_port == 0  # SCTP 端口未解析
        assert pkt.l7_proto == "unknown"

    def test_icmp_identification(self):
        raw = build_eth(build_ipv4("10.0.0.1", "203.0.113.9", 1, b"\x08\x00" + b"\x00" * 6))
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l4_proto == "icmp"


# ══════════════════════════════════════════════════════════════
# 链路层 / 边界情况
# ══════════════════════════════════════════════════════════════

class TestLinkLayer:
    """VLAN / PPPoE / 非 IP 包 / 截断包等链路层情况。"""

    def test_vlan_tagged_packet(self):
        """802.1Q VLAN 帧应被正确剥离并解析内层 IP。"""
        inner = build_ipv4("10.0.0.1", "93.184.216.34", 6, build_tcp(40000, 80, build_http_get("vlan.example.com")))
        # [dst+src+TPID(0x8100)] + [TCI(2B)] + [内层 ethertype 0x0800] + IP
        raw = build_eth(inner, eth_type=0x8100)[:14] + struct.pack("!HH", 0x0064, 0x0800) + inner
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l7_proto == "http"
        assert pkt.dst_port == 80

    def test_pppoe_ipv4_packet(self):
        """PPPoE Session 帧（0x8864）应剥离 PPP 头解析 IPv4。"""
        inner = build_ipv4("10.0.0.1", "93.184.216.34", 6, build_tcp(40000, 80, build_http_get()))
        pppoe = b"\x11\x00\x00\x01" + struct.pack("!H", len(inner) + 2) + b"\x00\x21" + inner
        raw = build_eth(pppoe, eth_type=0x8864)
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l7_proto == "http"
        assert pkt.src_ip == "10.0.0.1"

    def test_arp_not_ip_returns_none(self):
        raw = build_eth(b"\x00" * 28, eth_type=0x0806)
        assert parse_packet(raw) is None

    def test_truncated_ethernet(self):
        assert parse_packet(b"\x00" * 5) is None

    def test_truncated_ipv4(self):
        raw = build_eth(b"\x45\x00" + b"\x00" * 5)  # 不足 20 字节 IP 头
        assert parse_packet(raw) is None

    def test_non_standard_ethertype(self):
        raw = build_eth(b"\x00" * 46, eth_type=0x88CC)  # LLDP
        assert parse_packet(raw) is None

    def test_mac_address_parsing(self):
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 40000, 80, build_http_get()))
        assert pkt is not None
        assert pkt.src_mac == "00:11:22:33:44:55"
        assert pkt.dst_mac == "66:77:88:99:aa:bb"


# ══════════════════════════════════════════════════════════════
# pcap 回放集成测试 — 验证"真正捕获 + 解析"链路
# ══════════════════════════════════════════════════════════════

@pytest.mark.slow
@pytest.mark.asyncio
class TestPcapReplayProtocolCapture:
    """通过 pcap 回放完整走通 捕获 → 解析 → 流管理 → 存储 链路。

    注：DPIEngine.load() 使用固定搜索路径加载真实 libndpi_helper.so，
    dpi_lib_path 参数不参与路径解析，因此本测试实际运行在真实 nDPI 上。
    断言基于协议名（dns/http/ntp/ssh/tls/dhcp），nDPI 与端口回退结果一致，
    故对两条检测路径均成立。
    """

    async def _run_pipeline(self, tmp_path, sqlite_store, packets, assert_fn):
        from app.collector.pipeline import CapturePipeline

        pcap = str(tmp_path / "protocols.pcap")
        write_pcap(pcap, packets)

        pipeline = CapturePipeline(
            storage=sqlite_store,
            pcap_file=pcap,
            dpi_lib_path="/nonexistent/libndpi_helper.so",  # 不影响加载（见类注释）
            flush_interval=0.1,
            idle_timeout=0.1,
            stats_interval=100,
            pcap_output_enabled=False,
            tls_keylog_file="",
        )
        try:
            await pipeline.start()
            # 等待回放完成 + 定时刷流把超时流写入存储
            await asyncio.sleep(0.8)
            await pipeline.stop()
        finally:
            await pipeline.stop()

        await assert_fn(sqlite_store)

    async def test_replay_multi_protocol(self, tmp_path, sqlite_store):
        packets = [
            # DNS 查询 (UDP 53)
            build_udp_packet("192.0.2.10", "8.8.8.8", 40000, 53, build_dns_query("www.example.com", qid=1)),
            # HTTP GET (TCP 80)
            build_tcp_packet("192.0.2.10", "93.184.216.34", 40001, 80, build_http_get("www.example.com")),
            # NTP (UDP 123)
            build_udp_packet("192.0.2.10", "185.125.190.57", 40002, 123, build_ntp_packet()),
            # SSH (TCP 22)
            build_tcp_packet("192.0.2.10", "203.0.113.9", 40003, 22, build_ssh_banner()),
            # TLS ClientHello (TCP 443)
            build_tcp_packet("192.0.2.10", "93.184.216.34", 40004, 443, build_tls_clienthello("secure.example.com")),
            # DHCP (UDP 67)
            build_udp_packet("0.0.0.0", "255.255.255.255", 68, 67, build_dhcp_discover()),
        ]

        async def check(store):
            page = await store.query_conversations(page=1, size=50)
            flows = {c.l7_proto: c for c in page.items}
            assert flows.get("dns"), "DNS 流未被捕获"
            assert flows.get("http"), "HTTP 流未被捕获"
            assert flows.get("ntp"), "NTP 流未被捕获"
            assert flows.get("ssh"), "SSH 流未被捕获"
            assert flows.get("tls"), "TLS 流未被捕获"
            assert flows.get("dhcp"), "DHCP 流未被捕获"

            # 验证元数据：HTTP 的 l7_meta 应含请求行/Host
            http = flows["http"]
            assert http.l7_meta, "HTTP 流缺少 l7_meta"
            assert "GET /index.html HTTP/1.1" in http.l7_meta
            assert "www.example.com" in http.l7_meta

            # TLS 流应有 SNI（存在 dst_host 字段）
            tls = flows["tls"]
            assert tls.dst_host == "secure.example.com", f"TLS 流缺少 SNI: dst_host={tls.dst_host!r}"

        await self._run_pipeline(tmp_path, sqlite_store, packets, check)

    async def test_replay_dns_metadata(self, tmp_path, sqlite_store):
        """DNS 查询 + 响应应累积为 l7_meta 中的请求/响应内容。"""
        packets = [
            # DNS 查询
            build_udp_packet("192.0.2.20", "8.8.8.8", 50000, 53, build_dns_query("www.baidu.com", qid=0xABCD)),
            # DNS 响应（同一条流）
            build_udp_packet("8.8.8.8", "192.0.2.20", 53, 50000, build_dns_response("www.baidu.com", "157.148.69.186", qid=0xABCD)),
        ]

        async def check(store):
            page = await store.query_conversations(page=1, size=50, l7_proto="dns")
            assert page.items, "DNS 流未被捕获"
            dns = page.items[0]
            assert "DNS 请求: www.baidu.com (A)" in (dns.l7_meta or ""), f"缺少请求元数据: {dns.l7_meta}"
            assert "www.baidu.com -> 157.148.69.186 (A)" in (dns.l7_meta or ""), f"缺少响应元数据: {dns.l7_meta}"

        await self._run_pipeline(tmp_path, sqlite_store, packets, check)
