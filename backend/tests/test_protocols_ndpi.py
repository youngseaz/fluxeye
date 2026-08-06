"""nDPI 真实 DPI 检测测试 — 复用 test_protocols.py 的报文构建器。

验证：
  1. nDPI 检测结果与端口回退一致（大小写归一化后）
  2. nDPI 的增强检测能力（比端口回退更强：SOCKS5 / HTTP2）
  3. nDPI 已知的协议细分差异（FTP control/data、RESP、QUIC 内层 Google）
  4. 多包会话检测（HTTP 三次握手、HTTPS ClientHello、HTTP2 preface）
  5. pcap 回放 + 真实 nDPI 的端到端捕获链路

这些测试加载真实 libndpi_helper.so；若引擎不可用则自动跳过。
"""

from __future__ import annotations

import asyncio
import itertools

import pytest

from app.collector.dpi import create_dpi_engine
from app.collector.packet import parse_packet

from tests.test_protocols import (
    build_dhcp_discover,
    build_dns_query,
    build_http_get,
    build_ntp_packet,
    build_quic_initial,
    build_socks5_connect,
    build_ssh_banner,
    build_tcp_packet,
    build_tls_clienthello,
    build_udp_packet,
    write_pcap,
)

# 每个探测使用独立源端口，避免 flow key 冲突
# （get_flow_key 会对端点排序归一化，同 src:port→dst:port 会复用同一 nDPI 流）
_PORTS = itertools.count(60000)


@pytest.fixture(scope="module")
def ndpi_engine():
    """加载真实 nDPI 引擎；不可用则跳过整个模块的测试。"""
    try:
        engine = create_dpi_engine("libndpi_helper.so")
    except Exception:
        pytest.skip("无法加载 nDPI 桥接库 libndpi_helper.so")
    if not engine.is_available:
        pytest.skip("nDPI 引擎不可用")
    yield engine
    try:
        engine.unload()
    except Exception:
        pass


def _detect(engine, make_packet) -> tuple[str, str]:
    """用独立源端口构建报文，返回 (nDPI 小写结果, 端口回退结果)。"""
    sp = next(_PORTS)
    raw = make_packet(sp)
    pkt = parse_packet(raw)
    assert pkt is not None, "构建的报文应能被 parse_packet 解析"
    fk = engine.get_flow_key(pkt)
    result = engine.detect(pkt, flow_key=fk)
    return result.lower(), pkt.l7_proto


# ── nDPI 与端口回退一致的协议 ──────────────────────────
# (预期回退协议名, L4, 端口, 报文工厂)
MATCH_CASES = [
    pytest.param(
        "http", "tcp", 80,
        lambda sp: build_tcp_packet("10.0.0.1", "93.184.216.34", sp, 80, build_http_get()),
        id="http",
    ),
    pytest.param(
        "tls", "tcp", 443,
        lambda sp: build_tcp_packet("10.0.0.1", "93.184.216.34", sp, 443, build_tls_clienthello("www.example.com")),
        id="tls",
    ),
    pytest.param(
        "dns", "udp", 53,
        lambda sp: build_udp_packet("10.0.0.1", "8.8.8.8", sp, 53, build_dns_query("www.example.com")),
        id="dns",
    ),
    pytest.param(
        "ntp", "udp", 123,
        lambda sp: build_udp_packet("10.0.0.1", "185.125.190.57", sp, 123, build_ntp_packet()),
        id="ntp",
    ),
    pytest.param(
        "ssh", "tcp", 22,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 22, build_ssh_banner()),
        id="ssh",
    ),
    pytest.param(
        "dhcp", "udp", 67,
        lambda sp: build_udp_packet("0.0.0.0", "255.255.255.255", 68, 67, build_dhcp_discover()),
        id="dhcp",
    ),
    pytest.param(
        "smtp", "tcp", 25,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 25, b"EHLO client.example.com\r\n"),
        id="smtp",
    ),
    pytest.param(
        "mysql", "tcp", 3306,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 3306,
                                    b"\x0a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x34\x00\x00\x00\x00"),
        id="mysql",
    ),
    pytest.param(
        "telnet", "tcp", 23,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 23, b"login: "),
        id="telnet",
    ),
    pytest.param(
        "snmp", "udp", 161,
        lambda sp: build_udp_packet("10.0.0.1", "203.0.113.9", sp, 161, b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"),
        id="snmp",
    ),
    pytest.param(
        "ldap", "tcp", 389,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 389, b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"),
        id="ldap",
    ),
    pytest.param(
        "mongodb", "tcp", 27017,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 27017,
                                    b"\x3f\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00"),
        id="mongodb",
    ),
    pytest.param(
        "wireguard", "udp", 51820,
        lambda sp: build_udp_packet("10.0.0.1", "203.0.113.9", sp, 51820, b"\x01\x00\x00\x00" + b"\x00" * 28),
        id="wireguard",
    ),
    pytest.param(
        "openvpn", "udp", 1194,
        lambda sp: build_udp_packet("10.0.0.1", "203.0.113.9", sp, 1194, b"\x38\x01\x00\x00\x00\x00\x00\x00"),
        id="openvpn",
    ),
    pytest.param(
        "sip", "udp", 5060,
        lambda sp: build_udp_packet("10.0.0.1", "203.0.113.9", sp, 5060,
                                    b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1\r\n\r\n"),
        id="sip",
    ),
    pytest.param(
        "mdns", "udp", 5353,
        lambda sp: build_udp_packet("10.0.0.1", "224.0.0.251", sp, 5353,
                                    b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                                    + b"\x04_http\x04_tcp\x05local\x00\x00\x0c\x00\x01"),
        id="mdns",
    ),
    pytest.param(
        "pop3", "tcp", 110,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 110, b"+OK Dovecot ready.\r\n"),
        id="pop3",
    ),
    pytest.param(
        "imap", "tcp", 143,
        lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 143, b"* OK [CAPABILITY IMAP4rev1] server ready\r\n"),
        id="imap",
    ),
]


@pytest.mark.slow
class TestNDPIMatchesPortFallback:
    """nDPI 检测结果应与端口回退一致（大小写归一化后）。"""

    @pytest.mark.parametrize("name,l4,port,factory", MATCH_CASES)
    def test_ndpi_matches_fallback(self, ndpi_engine, name, l4, port, factory):
        ndpi_result, fallback = _detect(ndpi_engine, factory)
        assert fallback == name, f"端口回退应识别 {name}，实际 {fallback}"
        assert ndpi_result == fallback, (
            f"{name}(port {port}): nDPI={ndpi_result!r} 应与端口回退={fallback!r} 一致"
        )


@pytest.mark.slow
class TestNDPIEnhancedDetection:
    """nDPI 比端口回退更强：能识别回退无法识别的协议。"""

    def test_socks5_on_port_1080(self, ndpi_engine):
        """1080 不在端口映射表，回退=unknown，但 nDPI 能识别 SOCKS。"""
        ndpi_result, fallback = _detect(
            ndpi_engine,
            lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 1080,
                                        build_socks5_connect("proxy.example.com")),
        )
        assert fallback == "unknown"
        assert ndpi_result == "socks"

    def test_http2_preface(self, ndpi_engine):
        """HTTP/2 preface 在 80 端口：回退=http，nDPI 细分为 http2。"""
        h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
        ndpi_result, fallback = _detect(
            ndpi_engine,
            lambda sp: build_tcp_packet("10.0.0.1", "93.184.216.34", sp, 80, h2),
        )
        assert fallback == "http"
        assert ndpi_result == "http2"


@pytest.mark.slow
class TestNDPIProtocolDivergences:
    """nDPI 已知的协议细分差异（与端口回退命名不同，属正常现象）。"""

    def test_ftp_split_control_data(self, ndpi_engine):
        """nDPI 将 FTP 拆分为 ftp_control / ftp_data，回退统一为 ftp。"""
        ndpi_result, fallback = _detect(
            ndpi_engine,
            lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 21, b"USER anonymous\r\n"),
        )
        assert fallback == "ftp"
        assert ndpi_result == "ftp_control"

    def test_redis_resp_protocol(self, ndpi_engine):
        """nDPI 返回底层协议名 resp（RESP 协议），而非服务名 redis。"""
        ndpi_result, fallback = _detect(
            ndpi_engine,
            lambda sp: build_tcp_packet("10.0.0.1", "203.0.113.9", sp, 6379, b"*1\r\n$4\r\nPING\r\n"),
        )
        assert fallback == "redis"
        assert ndpi_result == "resp"

    def test_quic_inner_google_protocol(self, ndpi_engine):
        """QUIC 流量 nDPI 会继续解析内层应用协议（Google），而非仅报 quic。"""
        ndpi_result, fallback = _detect(
            ndpi_engine,
            lambda sp: build_udp_packet("10.0.0.1", "8.8.8.8", sp, 4433, build_quic_initial()),
        )
        assert fallback == "quic"
        assert ndpi_result == "google"


@pytest.mark.slow
class TestNDPIMultiPacketSessions:
    """多包会话：同一流的 nDPI 检测应稳定且正确。"""

    def test_http_three_way_handshake(self, ndpi_engine):
        """HTTP 会话：SYN → SYN-ACK → GET，全程识别为 http。"""
        sp = next(_PORTS)
        dst = "93.184.216.34"
        flow_key = None
        results = []
        for payload, flags in [(b"", 0x02), (b"", 0x12), (build_http_get(), 0x18)]:
            pkt = parse_packet(build_tcp_packet("10.0.0.1", dst, sp, 80, payload, flags))
            assert pkt is not None
            if flow_key is None:
                flow_key = ndpi_engine.get_flow_key(pkt)
            results.append(ndpi_engine.detect(pkt, flow_key=flow_key).lower())
        assert results == ["http", "http", "http"], results

    def test_https_clienthello_session(self, ndpi_engine):
        """HTTPS 会话：SYN（端口猜测 tls）→ ClientHello（内容确认 tls）。"""
        sp = next(_PORTS)
        dst = "93.184.216.34"
        flow_key = None
        results = []
        for payload, flags in [(b"", 0x02), (build_tls_clienthello("www.example.com"), 0x18)]:
            pkt = parse_packet(build_tcp_packet("10.0.0.1", dst, sp, 443, payload, flags))
            assert pkt is not None
            if flow_key is None:
                flow_key = ndpi_engine.get_flow_key(pkt)
            results.append(ndpi_engine.detect(pkt, flow_key=flow_key).lower())
        assert results == ["tls", "tls"], results

    def test_http2_session(self, ndpi_engine):
        """HTTP/2 preface 应识别为 http2。"""
        h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
        ndpi_result, fallback = _detect(
            ndpi_engine,
            lambda sp: build_tcp_packet("10.0.0.1", "93.184.216.34", sp, 80, h2),
        )
        assert ndpi_result == "http2"


@pytest.mark.slow
@pytest.mark.asyncio
class TestNDPIPcapReplay:
    """pcap 回放 + 真实 nDPI 的端到端链路：捕获 → DPI → 存储。"""

    async def test_replay_with_real_ndpi(self, tmp_path, sqlite_store):
        from app.collector.pipeline import CapturePipeline

        packets = [
            # DNS (UDP 53) — 两路径一致
            build_udp_packet("192.0.2.10", "8.8.8.8", 40000, 53, build_dns_query("www.example.com")),
            # HTTP (TCP 80) — 两路径一致
            build_tcp_packet("192.0.2.10", "93.184.216.34", 40001, 80, build_http_get("www.example.com")),
            # SOCKS5 (TCP 1080) — 仅 nDPI 能识别，回退为 unknown
            build_tcp_packet("192.0.2.10", "203.0.113.9", 40002, 1080, build_socks5_connect("proxy.example.com")),
            # HTTP/2 (TCP 80) — nDPI 细分为 http2
            build_tcp_packet("192.0.2.10", "93.184.216.34", 40003, 80,
                             b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"),
        ]
        pcap = str(tmp_path / "ndpi.pcap")
        write_pcap(pcap, packets)

        pipeline = CapturePipeline(
            storage=sqlite_store,
            pcap_file=pcap,
            dpi_lib_path="libndpi_helper.so",  # load() 使用固定搜索路径加载真实库
            flush_interval=0.1,
            idle_timeout=0.1,
            stats_interval=100,
            pcap_output_enabled=False,
        )
        try:
            await pipeline.start()
            await asyncio.sleep(0.8)
        finally:
            await pipeline.stop()

        page = await sqlite_store.query_conversations(page=1, size=50)
        flows = {c.l7_proto: c for c in page.items}
        assert flows.get("dns"), "DNS 流未被 nDPI 识别"
        assert flows.get("http"), "HTTP 流未被 nDPI 识别"
        assert flows.get("socks"), "SOCKS 流应被 nDPI 识别 (1080 端口)"
        assert flows.get("http2"), "HTTP/2 流应被 nDPI 识别为 http2"
