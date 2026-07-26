"""pytest 共享 fixtures 和配置。"""

from __future__ import annotations

import os
import tempfile
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from app.collector.packet import parse_packet, ParsedPacket
from app.config import SQLiteConfig
from app.flow.manager import FlowManager
from app.models.schemas import FlowRecord
from app.storage.sqlite_store import SQLiteStore


# ── pytest 配置 ───────────────────────────────────────

def pytest_configure(config):
    """注册自定义标记。"""
    config.addinivalue_line("markers", "slow: 慢速测试（如 pcap 回放）")


# ── 通用 Fixtures ─────────────────────────────────────

@pytest.fixture
def sample_packet_tcp_syn() -> ParsedPacket | None:
    """合成一个 TCP SYN 包。"""
    import struct
    eth = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x0800)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 64, 6, 0,
                     bytes([10, 0, 0, 1]), bytes([192, 168, 1, 1]))
    raw = eth + ip + struct.pack('!HHIIBBHHH', 40000, 80, 0, 0, 0x52, 0, 0, 0, 0)
    return parse_packet(raw)


@pytest.fixture
def sample_packet_http_get() -> ParsedPacket | None:
    """合成一个 HTTP GET 包（含 payload）。"""
    import struct
    http_data = b'GET /index.html HTTP/1.1\r\nHost: test.com\r\n\r\n'
    eth = struct.pack('!6s6sH', b'\x00' * 6, b'\x00' * 6, 0x0800)
    total_ip = 20 + 20 + len(http_data)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_ip, 0, 0, 64, 6, 0,
                     bytes([10, 0, 0, 1]), bytes([93, 184, 216, 34]))
    raw = eth + ip + struct.pack('!HHIIBBHHH', 40000, 80, 1, 1, 0x50, 0, 0, 0, 0) + http_data
    return parse_packet(raw)


@pytest.fixture
def sample_flow_record() -> FlowRecord:
    """合成一条流记录。"""
    from datetime import datetime, timezone
    return FlowRecord(
        timestamp=datetime.now(timezone.utc),
        src_mac="00:11:22:33:44:01",
        dst_mac="00:11:22:33:44:02",
        src_ip="10.0.0.1",
        dst_ip="192.168.1.1",
        src_port=40000,
        dst_port=443,
        l4_proto="tcp",
        l7_proto="tls",
        bytes_sent=1000,
        bytes_recv=2000,
        packets_sent=5,
        packets_recv=10,
        l7_meta="test.example.com",
        duration_ms=5000,
    )


# ── 存储 Fixtures ─────────────────────────────────────

@pytest_asyncio.fixture
async def sqlite_store() -> AsyncGenerator[SQLiteStore, None]:
    """创建一个临时 SQLite 存储后端。"""
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    store = SQLiteStore(SQLiteConfig(path=path))
    await store.initialize()
    yield store
    await store.close()
    if os.path.exists(path):
        os.unlink(path)


@pytest_asyncio.fixture
async def sqlite_store_with_data(sqlite_store: SQLiteStore) -> SQLiteStore:
    """预填充数据的存储后端。"""
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    records = []
    for i in range(20):
        records.append(FlowRecord(
            timestamp=now - timedelta(seconds=i * 30),
            src_mac=f"00:11:22:33:44:{i % 5 + 1:02x}",
            dst_mac=f"00:11:22:33:55:{i % 3 + 1:02x}",
            src_ip=f"10.0.0.{i % 5 + 1}",
            dst_ip=f"192.168.1.{i % 3 + 1}",
            src_port=40000 + i,
            dst_port=443 if i % 2 == 0 else 80,
            l4_proto="tcp",
            l7_proto="tls" if i % 2 == 0 else "http",
            bytes_sent=1000 * (i + 1),
            bytes_recv=500 * (i + 1),
            packets_sent=i + 1,
            packets_recv=i + 1,
            l7_meta=f"host{i}.example.com",
            duration_ms=1000 * (i + 1),
        ))
    await sqlite_store.write_flows_batch(records)
    return sqlite_store


# ── 流管理器 Fixtures ─────────────────────────────────

@pytest.fixture
def flow_manager() -> FlowManager:
    """创建一个流管理器。"""
    return FlowManager(idle_timeout=60)
