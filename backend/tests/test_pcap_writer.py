"""PcapWriter 单元测试 — 文件写入、分段轮转、旧文件清理。"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from app.collector.packet import ParsedPacket
from app.collector.pcap_writer import PcapWriter


def _make_packet(raw: bytes) -> ParsedPacket:
    return ParsedPacket(
        timestamp=datetime.now(timezone.utc),
        src_mac="00:11:22:33:44:55",
        dst_mac="66:77:88:99:aa:bb",
        src_ip="10.0.0.1",
        dst_ip="93.184.216.34",
        src_port=40000,
        dst_port=80,
        l4_proto="tcp",
        l7_proto="http",
        payload=raw,
        ip_header_len=20,
        total_len=len(raw) + 40,
        raw=raw,
    )


def _read_global_header(path):
    with open(path, "rb") as f:
        return f.read(24)


class TestPcapWriterOpen:
    def test_open_creates_dir_and_file(self, tmp_path):
        out = tmp_path / "captures"
        writer = PcapWriter(output_dir=str(out))
        writer.open()
        writer.close()  # 关闭并 flush 缓冲后再读取
        assert out.exists()
        # 应生成一个文件且以全局头开头
        files = list(out.glob("*.pcap"))
        assert len(files) == 1
        header = _read_global_header(files[0])
        # 小端 magic 0xa1b2c3d4
        assert struct.unpack("<I", header[:4])[0] == 0xA1B2C3D4
        assert writer.packets_written == 0
        assert writer.current_file is not None

    def test_open_without_write_close(self, tmp_path):
        writer = PcapWriter(output_dir=str(tmp_path))
        writer.open()
        writer.close()
        assert writer.packets_written == 0
        # close 后 current_file 仍指向最后创建的文件路径
        assert isinstance(writer.current_file, str)
        assert writer.current_file.endswith(".pcap")


class TestPcapWriterWrite:
    def test_write_appends_packet(self, tmp_path):
        writer = PcapWriter(output_dir=str(tmp_path))
        writer.open()
        raw = b"\x00" * 64
        writer.write(_make_packet(raw))
        writer.close()

        files = list(tmp_path.glob("*.pcap"))
        assert len(files) == 1
        with open(files[0], "rb") as f:
            data = f.read()
        # 全局头 24 + 包记录头 16 + 数据 64
        assert len(data) == 24 + 16 + 64
        assert writer.packets_written == 1

    def test_write_before_open_is_noop(self, tmp_path):
        writer = PcapWriter(output_dir=str(tmp_path))
        writer.write(_make_packet(b"\x00" * 32))
        assert writer.packets_written == 0
        assert list(tmp_path.glob("*.pcap")) == []

    def test_multiple_packets(self, tmp_path):
        writer = PcapWriter(output_dir=str(tmp_path))
        writer.open()
        for _ in range(5):
            writer.write(_make_packet(b"\x01" * 32))
        writer.close()
        assert writer.packets_written == 5


class TestPcapWriterRotation:
    def test_rotate_on_size_threshold(self, tmp_path):
        """达到 max_file_size 后应轮转生成新文件。"""
        writer = PcapWriter(
            output_dir=str(tmp_path),
            max_file_size=24 + 16 + 20,  # 头 + 一条记录
        )
        writer.open()
        # 写多个包触发轮转（open 建 1 个 + 每次超限轮转）
        for _ in range(3):
            writer.write(_make_packet(b"\x02" * 20))
        writer.close()
        files = sorted(tmp_path.glob("*.pcap"))
        assert len(files) >= 2  # 至少发生一次轮转

    def test_cleanup_old_files(self, tmp_path):
        """超过 max_file_count 时应删除最旧文件。"""
        writer = PcapWriter(
            output_dir=str(tmp_path),
            max_file_size=24 + 16 + 10,
            max_file_count=2,
        )
        writer.open()
        for _ in range(5):
            writer.write(_make_packet(b"\x03" * 10))
        writer.close()
        files = sorted(tmp_path.glob("*.pcap"))
        assert len(files) == 2  # 只保留最新 2 个

    def test_current_file_updates_on_rotate(self, tmp_path):
        writer = PcapWriter(
            output_dir=str(tmp_path),
            max_file_size=24 + 16 + 10,
        )
        writer.open()
        first = writer.current_file
        writer.write(_make_packet(b"\x04" * 10))
        second = writer.current_file
        writer.close()
        assert first != second  # 轮转后当前文件变化


class TestPcapWriterFlush:
    def test_flush_writes_to_disk(self, tmp_path):
        writer = PcapWriter(output_dir=str(tmp_path))
        writer.open()
        writer.write(_make_packet(b"\x05" * 16))
        writer.flush()  # 不应抛异常
        writer.close()
        files = list(tmp_path.glob("*.pcap"))
        assert len(files) == 1
