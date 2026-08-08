"""大流量传输（视频/下载）不保存 pcap 的测试。"""

from __future__ import annotations

import asyncio
import struct

import pytest

from app.collector.capture import PcapReader

from tests.test_protocols import (
    build_tcp_packet,
    build_http_get,
    write_pcap,
)


class TestShouldCachePcap:
    """_should_cache_pcap 单元测试。"""

    def _pipeline(self, exclude_categories=(), exclude_protocols=()):
        from app.collector.pipeline import CapturePipeline
        return CapturePipeline(
            storage=None,
            pcap_exclude_categories=tuple(exclude_categories),
            pcap_exclude_protocols=tuple(exclude_protocols),
        )

    def test_normal_protocol_cached(self):
        pl = self._pipeline(exclude_protocols=["youtube"])
        assert pl._should_cache_pcap("k1", "http", "web") is True
        assert "k1" not in pl._pcap_excluded_keys

    def test_excluded_protocol_not_cached(self):
        pl = self._pipeline(exclude_protocols=["youtube", "bittorrent"])
        assert pl._should_cache_pcap("k2", "youtube", "video") is False
        assert "k2" in pl._pcap_excluded_keys

    def test_excluded_category_not_cached(self):
        pl = self._pipeline(exclude_categories=["video", "streaming"])
        assert pl._should_cache_pcap("k3", "https", "video") is False
        assert "k3" in pl._pcap_excluded_keys

    def test_flow_remembered_after_exclusion(self):
        """一旦某流被判定为大流量，后续包即使协议名不同也不再缓存。"""
        pl = self._pipeline(exclude_categories=["video"])
        # 首个包被判为 video
        assert pl._should_cache_pcap("k4", "tls", "video") is False
        # 后续包协议名不是 video，但因 flow 已被记住 → 仍不缓存
        assert pl._should_cache_pcap("k4", "tls", "web") is False

    def test_empty_flow_key_always_cached(self):
        pl = self._pipeline(exclude_protocols=["youtube"])
        assert pl._should_cache_pcap("", "youtube", "video") is True

    def test_case_insensitive(self):
        pl = self._pipeline(exclude_protocols=["YouTube"], exclude_categories=["Video"])
        assert pl._should_cache_pcap("k5", "YOUTUBE", "VIDEO") is False

    def test_default_no_exclusion(self):
        pl = self._pipeline()
        assert pl._should_cache_pcap("k6", "youtube", "video") is True


@pytest.mark.slow
@pytest.mark.asyncio
class TestPcapExcludeIntegration:
    """pcap 回放：排除的协议不写入缓存文件。"""

    @staticmethod
    def _read_payloads(pcap_path: str) -> list[bytes]:
        r = PcapReader(pcap_path)
        r.open()
        payloads = []
        for pkt in r:
            if pkt:
                payloads.append(pkt.payload)
        r.close()
        return payloads

    async def test_http2_excluded_http_cached(self, tmp_path, sqlite_store):
        from app.collector.pipeline import CapturePipeline

        http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00" * 9
        packets = [
            # HTTP (port 80) — 不应被排除
            build_tcp_packet("192.0.2.50", "93.184.216.34", 56001, 80,
                             build_http_get("www.cache-test.com")),
            # HTTP/2 (port 80, preface) — nDPI 识别为 http2，应被排除
            build_tcp_packet("192.0.2.51", "93.184.216.34", 56002, 80, http2_preface),
        ]
        cache_dir = tmp_path / "cache"
        pcap = str(tmp_path / "in.pcap")
        write_pcap(pcap, packets)

        pipeline = CapturePipeline(
            storage=sqlite_store,
            pcap_file=pcap,
            pcap_output_enabled=True,
            pcap_output_dir=str(cache_dir),
            pcap_exclude_protocols=("http2",),
            flush_interval=0.1,
            idle_timeout=0.1,
            stats_interval=100,
            tls_keylog_file="",
        )
        try:
            await pipeline.start()
            await asyncio.sleep(0.8)
        finally:
            await pipeline.stop()

        # 读取缓存写入的文件
        files = list(cache_dir.glob("*.pcap"))
        assert files, "缓存目录应有 pcap 文件"
        payloads = []
        for f in files:
            payloads.extend(self._read_payloads(str(f)))
        joined = b"".join(payloads)
        # HTTP 请求应被缓存
        assert b"GET /index.html HTTP/1.1" in joined, "HTTP 包应被缓存"
        # HTTP/2 preface 应被排除
        assert b"PRI * HTTP/2.0" not in joined, "HTTP/2 包不应被缓存（已按协议排除）"

    async def test_no_exclusion_caches_all(self, tmp_path, sqlite_store):
        from app.collector.pipeline import CapturePipeline

        packets = [
            build_tcp_packet("192.0.2.52", "93.184.216.34", 56003, 80,
                             build_http_get("www.all-test.com")),
        ]
        cache_dir = tmp_path / "cache2"
        pcap = str(tmp_path / "in2.pcap")
        write_pcap(pcap, packets)

        pipeline = CapturePipeline(
            storage=sqlite_store,
            pcap_file=pcap,
            pcap_output_enabled=True,
            pcap_output_dir=str(cache_dir),
            flush_interval=0.1,
            idle_timeout=0.1,
            stats_interval=100,
            tls_keylog_file="",
        )
        try:
            await pipeline.start()
            await asyncio.sleep(0.8)
        finally:
            await pipeline.stop()

        files = list(cache_dir.glob("*.pcap"))
        assert files
        joined = b"".join(p for f in files for p in self._read_payloads(str(f)))
        assert b"GET /index.html HTTP/1.1" in joined
