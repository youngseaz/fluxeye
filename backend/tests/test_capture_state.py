"""capture_state 单元测试 — 抓包状态持久化的保存/读取/清除。"""

from __future__ import annotations

import json

import app.collector.capture_state as cs


class TestCaptureState:
    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cs, "STATE_FILE", tmp_path / "capture_state.json")
        cs.save_capture_state("eth0,lo", True)
        state = cs.load_capture_state()
        assert state == {"interface": "eth0,lo", "running": True}

    def test_load_missing_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cs, "STATE_FILE", tmp_path / "capture_state.json")
        assert cs.load_capture_state() == {}

    def test_clear_removes_file(self, tmp_path, monkeypatch):
        state_file = tmp_path / "capture_state.json"
        monkeypatch.setattr(cs, "STATE_FILE", state_file)
        cs.save_capture_state("eth0", False)
        assert state_file.exists()
        cs.clear_capture_state()
        assert not state_file.exists()
        assert cs.load_capture_state() == {}

    def test_save_creates_parent_dir(self, tmp_path, monkeypatch):
        state_file = tmp_path / "nested" / "dir" / "capture_state.json"
        monkeypatch.setattr(cs, "STATE_FILE", state_file)
        cs.save_capture_state("lo", True)
        assert state_file.exists()
        data = json.loads(state_file.read_text(encoding="utf-8"))
        assert data["running"] is True

    def test_load_corrupted_file_returns_empty(self, tmp_path, monkeypatch):
        state_file = tmp_path / "capture_state.json"
        monkeypatch.setattr(cs, "STATE_FILE", state_file)
        state_file.write_text("{invalid json", encoding="utf-8")
        assert cs.load_capture_state() == {}

    def test_clear_missing_file_no_error(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cs, "STATE_FILE", tmp_path / "none.json")
        cs.clear_capture_state()  # 不应抛异常
