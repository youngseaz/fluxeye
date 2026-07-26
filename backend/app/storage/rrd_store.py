"""RRDtool 时序存储 — 独立于主存储后端，始终启用。"""

from __future__ import annotations

import time
from pathlib import Path


class RRDStore:
    """RRDtool 环形时序数据库封装。

    始终启用，独立于主存储后端 (SQLite/InfluxDB/ClickHouse)。
    用于存储 1s 粒度的实时流量指标。
    """

    RRAS = (
        "RRA:AVERAGE:0.5:1:3600",    # 1s  精度, 保留 1h
        "RRA:AVERAGE:0.5:5:17280",   # 5s  精度, 保留 24h
        "RRA:AVERAGE:0.5:60:10080",  # 1m  精度, 保留 7d
        "RRA:AVERAGE:0.5:300:8640",  # 5m  精度, 保留 30d
    )

    DS_TEMPLATE = (
        "DS:bps:GAUGE:60:0:U",
        "DS:pps:GAUGE:60:0:U",
        "DS:flow_rate:GAUGE:60:0:U",
    )

    def __init__(self, rrd_dir: str = "./data/rrd") -> None:
        self.rrd_dir = Path(rrd_dir)
        self.rrd_path = self.rrd_dir / "traffic.rrd"

    def initialize(self) -> None:
        """初始化 RRD 文件（不存在则创建）。"""
        self.rrd_dir.mkdir(parents=True, exist_ok=True)

        if not self.rrd_path.exists():
            self._create()

    def _create(self) -> None:
        """创建 RRD 数据库。"""
        import rrdtool

        rrdtool.create(
            str(self.rrd_path),
            "--step", "1",
            *self.DS_TEMPLATE,
            *self.RRAS,
        )

    def update(self, bps: float, pps: float, flow_rate: float) -> None:
        """写入一个时间点的数据。"""
        import rrdtool

        now = int(time.time())
        rrdtool.update(
            str(self.rrd_path),
            f"{now}:{bps:.0f}:{pps:.0f}:{flow_rate:.0f}",
        )

    def fetch(self, resolution: str = "1s") -> list[tuple]:
        """获取时序数据。"""
        import rrdtool

        res_map = {"1s": 1, "5s": 5, "1m": 60, "5m": 300}
        step = res_map.get(resolution, 1)

        results = rrdtool.fetch(str(self.rrd_path), "AVERAGE", "--resolution", str(step))
        _, _, data = results
        return data
