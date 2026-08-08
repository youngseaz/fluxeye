"""PcapWriter 按时间保留策略测试。"""

from __future__ import annotations

import os
import time

from app.collector.pcap_writer import PcapWriter


class TestPcapWriterAgeRetention:
    """max_file_age_seconds 时间保留测试。"""

    def _make_writer(self, tmp_path, age: int | None):
        return PcapWriter(
            output_dir=str(tmp_path),
            filename_prefix="fluxeye",
            max_file_size=10 * 1024 * 1024,
            max_file_count=2,          # 故意设很小，验证时间策略优先于数量策略
            max_file_age_seconds=age,
        )

    def test_cleanup_expired_removes_old_files(self, tmp_path):
        writer = self._make_writer(tmp_path, age=None)
        # 手工创建 2 个新旧文件
        old = tmp_path / "fluxeye_old_001.pcap"
        new = tmp_path / "fluxeye_new_002.pcap"
        old.write_bytes(b"\x00" * 24)
        new.write_bytes(b"\x00" * 24)
        # 把旧文件 mtime 改到 8 天前
        old_time = time.time() - 8 * 86400
        os.utime(old, (old_time, old_time))

        deleted = writer.cleanup_expired(max_age_seconds=7 * 86400)
        assert deleted == 1
        assert not old.exists()
        assert new.exists()

    def test_cleanup_expired_keeps_recent(self, tmp_path):
        writer = self._make_writer(tmp_path, age=None)
        f = tmp_path / "fluxeye_recent_001.pcap"
        f.write_bytes(b"\x00" * 24)
        assert writer.cleanup_expired(max_age_seconds=7 * 86400) == 0
        assert f.exists()

    def test_age_policy_overrides_count(self, tmp_path):
        """配置了时间保留后，_cleanup_old 不应因文件数量多而删新文件。"""
        writer = self._make_writer(tmp_path, age=7 * 86400)
        writer.open()
        writer.close()
        # 制造 5 个"新"文件（小于保留时长），max_file_count=2 但不应触发数量删除
        for i in range(5):
            p = tmp_path / f"fluxeye_fake_{i:03d}.pcap"
            if not p.exists():
                p.write_bytes(b"\x00" * 24)
        writer._cleanup_old()
        # 时间策略下不应删除任何文件
        files = list(tmp_path.glob("fluxeye_*.pcap"))
        assert len(files) == 6  # 5 假 + 1 真(open 创建的)

    def test_count_policy_when_no_age(self, tmp_path):
        """未配置时间保留时退回按数量清理。"""
        writer = self._make_writer(tmp_path, age=None)
        writer.open()
        writer.close()
        for i in range(5):
            (tmp_path / f"fluxeye_extra_{i:03d}.pcap").write_bytes(b"\x00" * 24)
        writer._cleanup_old()
        files = list(tmp_path.glob("fluxeye_*.pcap"))
        assert len(files) <= 2  # max_file_count=2
