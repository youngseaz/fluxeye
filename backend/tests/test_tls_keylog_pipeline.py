"""TLS Key Log 与流量关联的端到端测试。

验证 FluxEye 对 SSLKEYLOGFILE 的完整链路：
  1. 单元：_extract_client_random 能从 TLS ClientHello 提取 client_random
  2. 集成：pcap 回放含 TLS ClientHello + SSLKEYLOGFILE → 流被标记 tls_key_available=true

说明：FluxEye 本身不执行 TLS 解密，只做「密钥可用性关联」——
      把 ClientHello 的 client_random 与 SSLKEYLOGFILE 匹配，标记哪些流
      的密钥可用（可导出 pcap + keylog 到 Wireshark/tshark 离线解密）。
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from app.collector.packet import parse_packet
from app.collector.tls_keylog import TLSKeyLogParser

from tests.test_protocols import build_tcp_packet, write_pcap

# 已知的 32 字节 client_random（hex）
CLIENT_RANDOM = "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809"
MASTER_SECRET = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" \
                "2122232425262728292a2b2c2d2e2f30"


def _build_clienthello(sni: str = "key.test.com") -> bytes:
    """构造 TLS ClientHello，random 为固定的 CLIENT_RANDOM。"""
    random = bytes.fromhex(CLIENT_RANDOM)
    sni_bytes = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    cipher = struct.pack("!H", 0x1301)  # TLS_AES_128_GCM_SHA256
    body = (
        struct.pack("!H", 0x0303)        # client_version
        + random                         # 32 字节 random
        + b"\x00"                        # session_id_len
        + struct.pack("!H", len(cipher)) + cipher
        + b"\x01\x00"                    # compression
        + struct.pack("!H", len(sni_ext)) + sni_ext
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


class TestExtractClientRandom:
    """_extract_client_random 单元测试。"""

    def _pipeline(self):
        from app.collector.pipeline import CapturePipeline
        # 不启动，仅实例化以调用方法
        return CapturePipeline(storage=None)

    def test_extract_from_clienthello(self):
        pl = self._pipeline()
        payload = _build_clienthello()
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 54001, 443, payload))
        assert pkt is not None
        assert pl._extract_client_random(pkt) == CLIENT_RANDOM

    def test_extract_returns_empty_for_non_tls(self):
        pl = self._pipeline()
        # HTTP payload 不是 TLS 记录
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 54002, 80, b"GET / HTTP/1.1\r\n\r\n"))
        assert pkt is not None
        assert pl._extract_client_random(pkt) == ""

    def test_extract_returns_empty_for_short_payload(self):
        pl = self._pipeline()
        pkt = parse_packet(build_tcp_packet("10.0.0.1", "93.184.216.34", 54003, 443, b"\x16\x03\x01"))
        assert pkt is not None
        assert pl._extract_client_random(pkt) == ""

    def test_extract_returns_empty_for_udp(self):
        pl = self._pipeline()
        from tests.test_protocols import build_udp_packet
        pkt = parse_packet(build_udp_packet("10.0.0.1", "8.8.8.8", 54004, 443, _build_clienthello()))
        assert pkt is not None
        assert pl._extract_client_random(pkt) == ""


class TestKeyLogParserMatch:
    """TLSKeyLogParser 对已知 client_random 的匹配。"""

    def test_lookup_matching_random(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text(f"CLIENT_RANDOM {CLIENT_RANDOM} {MASTER_SECRET}\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        assert parser.reload() == 1
        entry = parser.lookup(CLIENT_RANDOM.lower())
        assert entry is not None
        assert entry.label == "CLIENT_RANDOM"
        assert entry.secret == MASTER_SECRET

    def test_lookup_no_match(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text(f"CLIENT_RANDOM {CLIENT_RANDOM} {MASTER_SECRET}\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        parser.reload()
        assert parser.lookup("deadbeef" * 8) is None


@pytest.mark.slow
@pytest.mark.asyncio
class TestPipelineKeylogCorrelation:
    """pcap 回放端到端：TLS 流应被标记 tls_key_available=true。"""

    async def _run(self, tmp_path, sqlite_store, keylog_exists: bool):
        from app.collector.pipeline import CapturePipeline

        # TLS ClientHello 包
        payload = _build_clienthello()
        pcap = str(tmp_path / "tls.pcap")
        write_pcap(pcap, [
            build_tcp_packet("192.0.2.40", "93.184.216.34", 55001, 443, payload),
        ])

        # SSLKEYLOGFILE
        keylog = tmp_path / "keys.log"
        if keylog_exists:
            keylog.write_text(f"CLIENT_RANDOM {CLIENT_RANDOM} {MASTER_SECRET}\n", encoding="utf-8")

        pipeline = CapturePipeline(
            storage=sqlite_store,
            pcap_file=pcap,
            tls_keylog_file=str(keylog) if keylog_exists else "",
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
        tls_flows = [c for c in page.items if c.l7_proto == "tls"]
        assert tls_flows, "TLS 流未被捕获"
        return tls_flows[0]

    async def test_flow_marked_key_available(self, tmp_path, sqlite_store):
        flow = await self._run(tmp_path, sqlite_store, keylog_exists=True)
        assert "tls_key_available=true" in (flow.l7_meta or ""), f"l7_meta={flow.l7_meta!r}"
        assert CLIENT_RANDOM in (flow.l7_meta or "")

    async def test_flow_not_marked_without_keylog(self, tmp_path, sqlite_store):
        flow = await self._run(tmp_path, sqlite_store, keylog_exists=False)
        assert "tls_key_available" not in (flow.l7_meta or "")
