#!/usr/bin/env python3
"""数据库初始化脚本 — 创建表结构并写入初始模拟数据。"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone

from app.config import settings
from app.models.schemas import FlowRecord
from app.storage import create_storage


async def init_database() -> None:
    """初始化数据库，创建表并插入模拟数据。"""
    print(f"[init] 初始化存储后端: {settings.storage.backend}")
    storage = create_storage()
    await storage.initialize()

    print("[init] 插入模拟数据...")
    protocols = ["http", "tls", "dns", "quic", "ssh", "rtmp", "smtp", "dhcp"]
    ips = [
        "192.168.1.1", "192.168.1.5", "192.168.1.8",
        "10.0.0.1", "10.0.0.2", "172.16.0.1",
        "8.8.8.8", "1.1.1.1", "203.0.113.50",
    ]
    now = datetime.now(timezone.utc)

    batch = []
    for i in range(500):
        ts = now - timedelta(seconds=random.randint(0, 3600))
        # 模拟 GeoIP 数据（仅对外部 IP）
        dst_ip = random.choice(ips)
        is_external = not dst_ip.startswith(("192.168.", "10.", "172.16."))
        flow = FlowRecord(
            timestamp=ts,
            src_ip=random.choice(ips),
            dst_ip=dst_ip,
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 53, 22, 25, 4433]),
            l4_proto=random.choice(["tcp", "udp"]),
            l7_proto=random.choice(protocols),
            bytes_sent=random.randint(64, 65535),
            bytes_recv=random.randint(64, 65535),
            packets_sent=random.randint(1, 100),
            packets_recv=random.randint(1, 100),
            l7_meta=random.choice(["", "example.com", "api.example.com", "cdn.example.com"]),
            duration_ms=random.randint(10, 30000),
            dst_country=random.choice(["US", "CN", "JP", "DE", "GB", ""]) if is_external else "",
            dst_city=random.choice(["", "Mountain View", "Beijing", "Tokyo", "Berlin", "London"]),
            dst_asn=random.choice([0, 15169, 13335, 8075, 16509]),
        )
        batch.append(flow)

    count = await storage.write_flows_batch(batch)
    print(f"[init] 写入 {count} 条模拟流记录完成")

    await storage.close()
    print("[init] 数据库初始化完成！")


if __name__ == "__main__":
    asyncio.run(init_database())
