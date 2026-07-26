"""
FluxEye 全局日志模块 — 统一日志输出格式与级别管理。

特性:
- 彩色终端输出 (structlog 风格)
- 文件日志轮转 (按大小/时间)
- 调用方模块名自动识别
- DEBUG 模式用于开发，INFO 用于生产
- 性能敏感路径使用 logger.log / 条件判断避免格式化开销
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# ── ANSI 颜色代码 ────────────────────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_COLORS = {
    "DEBUG": "\033[36m",       # Cyan
    "INFO": "\033[32m",        # Green
    "WARNING": "\033[33m",     # Yellow
    "ERROR": "\033[31m",       # Red
    "CRITICAL": "\033[41m",    # Red background
    "DIM": "\033[90m",         # Gray
}


class ColorfulFormatter(logging.Formatter):
    """带颜色的日志格式化器。"""

    def __init__(self, fmt: str, use_colors: bool = True):
        super().__init__(fmt)
        self.use_colors = use_colors and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        if not self.use_colors:
            return super().format(record)

        level_color = _COLORS.get(record.levelname, _RESET)
        level_name = f"{record.levelname:8s}"

        # 时间
        ts = self.formatTime(record, "%H:%M:%S")

        # 模块名缩短
        module = record.name
        if module.startswith("app."):
            module = module[4:]
        module_colored = f"{_DIM}{module}{_RESET}"

        # 消息
        msg = super().format(record)
        # 从格式化后的消息中提取纯消息部分
        if hasattr(self, '_fmt_no_extra'):
            msg = record.getMessage()
        else:
            msg = record.getMessage()

        return (
            f"{_DIM}{ts}{_RESET} "
            f"{level_color}{level_name}{_RESET} "
            f"{module_colored} "
            f"{msg}"
        )


def setup_logger(
    name: str = "fluxeye",
    level: str | int = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10 MB
    backup_count: int = 5,
    json_output: bool = False,
) -> logging.Logger:
    """配置并获取全局日志器。

    Args:
        name: 日志器名称，默认 'fluxeye'
        level: 日志级别，'DEBUG' | 'INFO' | 'WARNING' | 'ERROR'
        log_file: 日志文件路径，None 则只输出到 stderr
        max_bytes: 单个日志文件最大字节数
        backup_count: 保留的轮转文件数
        json_output: 是否输出 JSON 格式（用于日志采集系统）

    Returns:
        配置好的日志器实例
    """
    logger = logging.getLogger(name)
    logger.setLevel(level.upper() if isinstance(level, str) else level)
    logger.handlers.clear()

    # 控制台 handler (stderr)
    console_fmt = (
        "%(asctime)s.%(msecs)03d %(levelname)-8s %(name)-25s %(message)s"
    )
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(ColorfulFormatter(console_fmt))
    console.setLevel(logging.DEBUG)
    logger.addHandler(console)

    # 文件 handler (轮转)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_fmt = (
            "%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)s | %(message)s"
        )
        file_handler = RotatingFileHandler(
            log_path, maxBytes=max_bytes, backupCount=backup_count,
        )
        file_handler.setFormatter(logging.Formatter(file_fmt, datefmt="%Y-%m-%d %H:%M:%S"))
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)

    return logger


# ── 快捷函数 ─────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """获取子模块日志器，自动继承全局配置。"""
    return logging.getLogger(f"fluxeye.{name}")


# ── 性能敏感路径用条件日志 ───────────────────────────

def log_if(level: int, condition: bool, logger: logging.Logger, msg: str, *args):
    """仅在满足条件时记录日志，避免不必要的字符串格式化。"""
    if condition and logger.isEnabledFor(level):
        logger.log(level, msg, *args)


# ── 应用启动时初始化 ─────────────────────────────────

def init_logging(level: str = "INFO", log_file: Optional[str] = None):
    """初始化项目全局日志（应用启动时调用一次）。"""
    root = setup_logger("fluxeye", level=level, log_file=log_file)

    # 第三方库日志降级
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)

    root.info("日志系统初始化完成, level=%s, file=%s", level, log_file or "(stderr only)")
    return root
