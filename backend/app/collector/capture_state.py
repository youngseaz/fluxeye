"""采集状态持久化 — 记录上次使用的抓包网口。

用于后端重启（开发热重载 / 崩溃恢复）后自动恢复抓包，
避免 `/api/v1/traffic/live` 因流水线重建而长时间返回空列表。

状态文件: ./data/capture_state.json  (相对 backend 工作目录)
"""

from __future__ import annotations

import json
from pathlib import Path

from app.utils.logger import get_logger

logger = get_logger("collector.capture_state")

STATE_FILE = Path("./data/capture_state.json")


def save_capture_state(interface: str, running: bool) -> None:
    """记录当前抓包状态。"""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(
            json.dumps({"interface": interface, "running": running}),
            encoding="utf-8",
        )
        logger.info("采集状态已保存: interface=%s running=%s", interface, running)
    except Exception as e:  # noqa: BLE001 - 状态持久化失败不应影响主流程
        logger.warning("保存采集状态失败: %s", e)


def load_capture_state() -> dict:
    """读取上次抓包状态。"""
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        logger.warning("读取采集状态失败: %s", e)
    return {}


def clear_capture_state() -> None:
    """清除采集状态（如显式停止抓包）。"""
    try:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
    except Exception:  # noqa: BLE001
        pass
