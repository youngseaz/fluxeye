"""TLSKeyLogParser 单元测试 — SSLKEYLOGFILE 解析、增量热加载、查询。"""

from __future__ import annotations

from app.collector.tls_keylog import (
    TLSKeyLogParser,
    create_keylog_parser,
    detect_keylog_from_env,
)

SAMPLE_LINES = [
    "# comment line",
    "CLIENT_RANDOM 00aa11bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899 0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00aa11bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30",
    "SERVER_TRAFFIC_SECRET_0 00aa11bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899 202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
    "RSA 00bb22cc33dd44ee55ff66778899aabbccddeeff00112233445566778899aabbccdd",
]


class TestTLSKeyLogParser:
    def test_load_missing_file_returns_false(self, tmp_path):
        parser = TLSKeyLogParser(filepath=str(tmp_path / "nope.log"))
        assert parser.load() is False
        assert parser.is_available is False

    def test_load_empty_filepath(self):
        parser = TLSKeyLogParser(filepath="")
        assert parser.load() is False

    def test_load_existing_file(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text("\n".join(SAMPLE_LINES) + "\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        assert parser.load() is True
        assert parser.is_available is True

    def test_reload_parses_keys(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text("\n".join(SAMPLE_LINES) + "\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        count = parser.reload()
        # 密钥以 client_random 为 key：CLIENT_RANDOM/CLIENT_HANDSHAKE/SERVER_TRAFFIC 共享
        # 同一 random 去重为 1 条，RSA 使用不同 random 为 1 条 → 共 2 条
        assert count == 2
        assert parser.key_count == 2

    def test_incremental_reload(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text(SAMPLE_LINES[0] + "\n", encoding="utf-8")  # 仅注释
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        assert parser.reload() == 0

        # 追加新行（不同 client_random，可各自入库）
        with open(f, "a", encoding="utf-8") as fh:
            fh.write(SAMPLE_LINES[1] + "\n")   # CLIENT_RANDOM 00aa...
            fh.write(SAMPLE_LINES[3] + "\n")   # SERVER_TRAFFIC 00aa...（同 random，去重）
            fh.write(SAMPLE_LINES[4] + "\n")   # RSA 00bb...（不同 random）
        # 新 random 只有 00aa 与 00bb 两个 → 2 条
        assert parser.reload() == 2
        # 再次 reload 不重复计数
        assert parser.reload() == 0

    def test_lookup_case_insensitive(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text(SAMPLE_LINES[1] + "\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        parser.reload()
        entry = parser.lookup("00AA11BB22CC33DD44EE55FF66778899AABBCCDDEEFF00112233445566778899")
        assert entry is not None
        assert entry.label == "CLIENT_RANDOM"
        assert entry.secret == "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

    def test_lookup_missing(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text(SAMPLE_LINES[1] + "\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        parser.reload()
        assert parser.lookup("deadbeef") is None

    def test_find_by_label(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text("\n".join(SAMPLE_LINES) + "\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        parser.reload()
        randoms = parser.find_by_label("CLIENT_RANDOM")
        assert len(randoms) == 1
        # 3 行共享同一 random：去重保留首条 (CLIENT_RANDOM)，后续标签不入库
        assert parser.find_by_label("SERVER_TRAFFIC_SECRET_0") == []
        assert len(parser.find_by_label("RSA")) == 1

    def test_export_wireshark_format(self, tmp_path):
        f = tmp_path / "keys.log"
        f.write_text(SAMPLE_LINES[1] + "\n", encoding="utf-8")
        parser = TLSKeyLogParser(filepath=str(f))
        parser.load()
        parser.reload()
        out = parser.export_to_wireshark_format()
        assert out.startswith("# FluxEye exported TLS keys")
        assert "CLIENT_RANDOM" in out

    def test_reload_missing_file_returns_zero(self):
        parser = TLSKeyLogParser(filepath="/nonexistent/keys.log")
        assert parser.reload() == 0


class TestKeylogFactory:
    def test_create_parser_from_env(self, tmp_path, monkeypatch):
        f = tmp_path / "keys.log"
        f.write_text(SAMPLE_LINES[1] + "\n", encoding="utf-8")
        monkeypatch.setenv("SSLKEYLOGFILE", str(f))
        parser = create_keylog_parser()
        assert parser.is_available
        assert parser.key_count == 1

    def test_detect_from_env(self, monkeypatch):
        monkeypatch.setenv("SSLKEYLOGFILE", "/tmp/custom.log")
        assert detect_keylog_from_env() == "/tmp/custom.log"

    def test_create_parser_with_missing_path(self):
        parser = create_keylog_parser(filepath="/nonexistent/keys.log")
        assert parser.is_available is False
