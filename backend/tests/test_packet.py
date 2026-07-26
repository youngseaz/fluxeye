"""数据包解析单元测试。"""

from __future__ import annotations

import struct

import pytest

from app.collector.packet import (
    PORT_PROTO_MAP,
    _guess_l7_proto,
    parse_ethernet,
    parse_ipv4,
    parse_tcp,
    parse_packet,
)


class TestGuessL7Proto:
    """端口 → 协议猜测测试。"""

    def test_http_port_80(self):
        assert _guess_l7_proto(40000, 80) == "http"

    def test_https_port_443(self):
        assert _guess_l7_proto(40000, 443) == "tls"

    def test_dns_port_53(self):
        assert _guess_l7_proto(40000, 53) == "dns"

    def test_ssh_port_22(self):
        assert _guess_l7_proto(12345, 22) == "ssh"

    def test_unknown_port(self):
        assert _guess_l7_proto(9999, 12345) == "unknown"

    def test_src_port_fallback(self):
        """当 dst_port 不在映射中时，尝试 src_port。"""
        assert _guess_l7_proto(80, 9999) == "http"

    def test_all_known_ports(self):
        """验证所有已知端口都能正确映射。"""
        for port, expected in PORT_PROTO_MAP.items():
            result = _guess_l7_proto(9999, port)
            assert result == expected, f"端口 {port} → {result} ≠ {expected}"


class TestParseEthernet:
    """Ethernet 帧解析测试。"""

    def test_ipv4_ethertype(self):
        """验证 IPv4 (0x0800) 能被正确识别。"""
        data = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x0800) + b'\x45' + b'\x00' * 19
        ethertype, payload, src_mac, dst_mac = parse_ethernet(data)
        assert ethertype == 0x0800
        assert len(payload) == len(data) - 14
        assert src_mac == "00:00:00:00:00:00"
        assert dst_mac == "00:00:00:00:00:00"

    def test_short_frame(self):
        """过短的帧应返回 (0, b'', '', '')。"""
        data = b'\x00' * 10
        ethertype, payload, src_mac, dst_mac = parse_ethernet(data)
        assert ethertype == 0
        assert payload == b""
        assert src_mac == ""
        assert dst_mac == ""


class TestParseIPv4:
    """IPv4 头部解析测试。"""

    def test_basic_ip_header(self):
        """验证标准 20 字节 IP 头。"""
        data = struct.pack('!BBHHHBBH4s4s',
                           0x45, 0, 60, 0, 0, 64, 6, 0,
                           bytes([10, 0, 0, 1]), bytes([192, 168, 1, 1]))
        result = parse_ipv4(data)
        assert result is not None
        assert result["src_ip"] == "10.0.0.1"
        assert result["dst_ip"] == "192.168.1.1"
        assert result["protocol"] == 6  # TCP

    def test_ipv4_with_options(self):
        """验证带选项的 IP 头（IHL=6 -> 24 字节）。"""
        data = struct.pack('!BBHHHBBH4s4s',
                           0x46, 0, 64, 0, 0, 64, 6, 0,
                           bytes([10, 0, 0, 1]), bytes([192, 168, 1, 1]))
        data += b'\x00' * 4  # 4 字节选项
        result = parse_ipv4(data)
        assert result is not None
        assert result["ihl"] == 24

    def test_not_ipv4(self):
        """非 IPv4 的第一个 nibble 应返回 None。"""
        data = b'\x60' + b'\x00' * 19
        assert parse_ipv4(data) is None


class TestParseTCP:
    """TCP 头部解析测试。"""

    def test_syn_packet(self):
        """验证 SYN 包。"""
        data = struct.pack('!HHIIBBHHH', 40000, 80, 0, 0, 0x52, 0, 0, 0, 0)
        result = parse_tcp(data)
        assert result is not None
        assert result["src_port"] == 40000
        assert result["dst_port"] == 80
        assert len(result["payload"]) == 0  # SYN 包无 payload

    def test_data_packet(self):
        """验证带数据的 TCP 包。"""
        payload_data = b'GET / HTTP/1.1\r\n\r\n'
        data = struct.pack('!HHIIBBHHH', 40000, 80, 1, 1, 0x50, 0, 0, 0, 0)
        data += payload_data
        result = parse_tcp(data)
        assert result is not None
        assert result["payload"] == payload_data

    def test_short_header(self):
        """过短的 TCP 头应返回 None。"""
        data = b'\x00' * 10
        assert parse_tcp(data) is None


class TestParsePacket:
    """完整数据包解析测试。"""

    def test_tcp_syn_packet(self, sample_packet_tcp_syn):
        """验证 TCP SYN 包完整解析。"""
        pkt = sample_packet_tcp_syn
        assert pkt is not None
        assert pkt.src_ip == "10.0.0.1"
        assert pkt.dst_ip == "192.168.1.1"
        assert pkt.src_port == 40000
        assert pkt.dst_port == 80
        assert pkt.l4_proto == "tcp"
        assert pkt.l7_proto == "http"  # 端口猜测

    def test_http_get_packet(self, sample_packet_http_get):
        """验证 HTTP GET 包解析（含 payload）。"""
        pkt = sample_packet_http_get
        assert pkt is not None
        assert pkt.l4_proto == "tcp"
        assert pkt.l7_proto == "http"
        assert b"GET /index.html" in pkt.payload

    def test_non_ip_packet(self):
        """非 IP 包应返回 None。"""
        # ARP 包 (ethertype 0x0806)
        data = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x0806) + b'\x00' * 42
        assert parse_packet(data) is None

    def test_udp_dns_packet(self):
        """验证 UDP DNS 包。"""
        eth = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x0800)
        ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 42, 0, 0, 64, 17, 0,
                         bytes([10, 0, 0, 1]), bytes([8, 8, 8, 8]))
        udp = struct.pack('!HHHH', 40000, 53, 28, 0) + b'\x00' * 20  # DNS 查询
        raw = eth + ip + udp
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l4_proto == "udp"
        assert pkt.l7_proto == "dns"
        assert pkt.dst_port == 53

    def test_ipv6_tcp_packet(self):
        """验证 IPv6 TCP 包能被正确解析。"""
        import ipaddress
        eth = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x86DD)
        # IPv6 固定头: 40 字节
        # version(4) + traffic_class(8) + flow_label(20) = 4 bytes
        ver_tc_flow = struct.pack('!I', (6 << 28))  # version=6
        payload_len = 40  # TCP 20 + 伪数据 20
        next_header = 6  # TCP
        hop_limit = 64
        src_ip6 = ipaddress.IPv6Address("2001:db8::1").packed
        dst_ip6 = ipaddress.IPv6Address("2001:db8::2").packed
        ipv6_header = ver_tc_flow + struct.pack('!HBB', payload_len, next_header, hop_limit) + src_ip6 + dst_ip6
        # TCP SYN
        tcp = struct.pack('!HHIIBBHHH', 40000, 443, 0, 0, 0x50, 0x02, 8192, 0, 0) + b'\x00' * 20
        raw = eth + ipv6_header + tcp
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.src_ip == "2001:db8::1"
        assert pkt.dst_ip == "2001:db8::2"
        assert pkt.src_port == 40000
        assert pkt.dst_port == 443
        assert pkt.l4_proto == "tcp"
        assert pkt.l7_proto == "tls"

    def test_ipv6_udp_dns_packet(self):
        """验证 IPv6 UDP DNS 包。"""
        import ipaddress
        eth = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x86DD)
        ver_tc_flow = struct.pack('!I', (6 << 28))
        payload_len = 28  # UDP 8 + 20
        next_header = 17  # UDP
        hop_limit = 64
        src_ip6 = ipaddress.IPv6Address("fe80::1").packed
        dst_ip6 = ipaddress.IPv6Address("ff02::fb").packed
        ipv6_header = ver_tc_flow + struct.pack('!HBB', payload_len, next_header, hop_limit) + src_ip6 + dst_ip6
        udp = struct.pack('!HHHH', 40000, 53, 28, 0) + b'\x00' * 20
        raw = eth + ipv6_header + udp
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l4_proto == "udp"
        assert pkt.l7_proto == "dns"
        assert "fe80::1" in pkt.src_ip

    def test_ipv6_extension_headers(self):
        """验证 IPv6 扩展头能被跳过，正确找到 TCP。"""
        import ipaddress
        eth = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x86DD)
        # 带 Hop-by-Hop (0) 扩展头: next_hdr=0, hdr_ext_len=0 (8字节)
        src_ip6 = ipaddress.IPv6Address("2001:db8::10").packed
        dst_ip6 = ipaddress.IPv6Address("2001:db8::20").packed
        hopbyhop = struct.pack('!BB', 6, 0) + b'\x00' * 6  # next=TCP(6), len=0 → 8 bytes
        inner_tcp = struct.pack('!HHIIBBHHH', 40000, 80, 0, 0, 0x50, 0x02, 8192, 0, 0) + b'\x00' * 20
        payload_len = len(hopbyhop) + len(inner_tcp)
        ver_tc_flow = struct.pack('!I', (6 << 28))
        ipv6_header = ver_tc_flow + struct.pack('!HBB', payload_len, 0, 64) + src_ip6 + dst_ip6  # next=0 (HBH)
        raw = eth + ipv6_header + hopbyhop + inner_tcp
        pkt = parse_packet(raw)
        assert pkt is not None
        assert pkt.l4_proto == "tcp"
        assert pkt.dst_port == 80
