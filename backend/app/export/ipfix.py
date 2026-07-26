"""IPFIX (NetFlow v10) 导出器 — 将 DPI 流记录编码为 IPFIX 报文并发送到 Collector。

IPFIX 协议 (RFC 7011-7015) 基于模板的动态流导出协议。
本实现支持:
  - Template 模板动态注册
  - Data Record 数据记录发送
  - 标准 IPFIX 字段 + nDPI application_id 扩展
  - UDP 传输
"""

from __future__ import annotations

import logging
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional

from app.models.schemas import FlowRecord

logger = logging.getLogger("export.ipfix")

# ── IPFIX 常量 ────────────────────────────────────────

IPFIX_VERSION = 10

# Set IDs
TEMPLATE_SET_ID = 2
OPTION_TEMPLATE_SET_ID = 3

# IANA IPFIX 标准字段 ID
IPFIX_FIELD = {
    "BYTE_DELTA_COUNT": 1,
    "PACKET_DELTA_COUNT": 2,
    "PROTOCOL_IDENTIFIER": 4,
    "IP_CLASS_OF_SERVICE": 5,
    "TCP_CONTROL_BITS": 6,
    "SOURCE_TRANSPORT_PORT": 7,
    "SOURCE_IPV4_ADDRESS": 8,
    "INPUT_INTERFACE": 10,
    "DESTINATION_TRANSPORT_PORT": 11,
    "DESTINATION_IPV4_ADDRESS": 12,
    "EGRESS_INTERFACE": 14,
    "FLOW_START_MILLISECONDS": 22,
    "FLOW_END_MILLISECONDS": 21,
    "SOURCE_MAC_ADDRESS": 56,
    "DESTINATION_MAC_ADDRESS": 57,
    "APPLICATION_ID": 95,        # variable-length string
    "OBSERVATION_POINT_ID": 138,
    "INTERFACE_NAME": 252,        # variable-length string
}

# 企业专用字段 (Enterprise number: 0 = IANA)
FIELD_LENGTH = {
    1: 8,    # BYTE_DELTA_COUNT → unsigned64
    2: 8,    # PACKET_DELTA_COUNT → unsigned64
    4: 1,    # PROTOCOL_IDENTIFIER
    5: 1,    # IP_CLASS_OF_SERVICE
    6: 1,    # TCP_CONTROL_BITS
    7: 2,    # SOURCE_TRANSPORT_PORT
    8: 4,    # SOURCE_IPV4_ADDRESS
    10: 4,   # INPUT_INTERFACE
    11: 2,   # DESTINATION_TRANSPORT_PORT
    12: 4,   # DESTINATION_IPV4_ADDRESS
    14: 4,   # EGRESS_INTERFACE
    21: 8,   # FLOW_END_MILLISECONDS → dateTimeMilliseconds
    22: 8,   # FLOW_START_MILLISECONDS
    56: 6,   # SOURCE_MAC_ADDRESS
    57: 6,   # DESTINATION_MAC_ADDRESS
    95: 65535,  # APPLICATION_ID → variable length
    138: 4,  # OBSERVATION_POINT_ID
    252: 65535, # INTERFACE_NAME → variable length
}


# ── IPFIX 消息编码 ────────────────────────────────────

def _encode_seconds(ts: float) -> int:
    """将 Unix 时间戳转为 IPFIX 秒精度。"""
    return int(ts)


def _encode_milliseconds(ts: float) -> int:
    """将 Unix 时间戳转为 IPFIX 毫秒精度。"""
    return int(ts * 1000)


@dataclass
class IPFIXTemplateField:
    """IPFIX 模板字段描述。"""
    field_id: int
    length: int
    enterprise: int = 0  # 0 = IANA


class IPFIXTemplate:
    """IPFIX 模板定义。"""

    def __init__(self, template_id: int, fields: list[IPFIXTemplateField]):
        self.template_id = template_id
        self.fields = fields

    def encode(self) -> bytes:
        """编码模板到字节流。"""
        buf = bytearray()
        buf += struct.pack("!HH", self.template_id, len(self.fields))
        for f in self.fields:
            if f.enterprise != 0:
                buf += struct.pack("!HH", f.field_id | 0x8000, f.length)
                buf += struct.pack("!I", f.enterprise)
            else:
                buf += struct.pack("!HH", f.field_id, f.length)
        return bytes(buf)

    @property
    def total_field_count(self) -> int:
        return len(self.fields) + sum(
            1 for f in self.fields if f.enterprise != 0
        )

    @property
    def data_record_length(self) -> int:
        """计算单条数据记录的总长度。"""
        total = 0
        for f in self.fields:
            if f.length == 65535:
                total += 2  # variable-length: 1 byte for length prefix
            else:
                total += f.length
            if f.enterprise != 0:
                total += 4
        return total


class IPFIXMessage:
    """IPFIX 消息构建器。"""

    def __init__(self, observation_domain_id: int = 0):
        self.observation_domain_id = observation_domain_id
        self._sequence = 0
        self._buf = bytearray()
        self._sets: list[bytes] = []

    def add_template_set(self, template_id: int,
                         fields: list[IPFIXTemplateField]) -> int:
        """注册并编码一个模板集。"""
        template = IPFIXTemplate(template_id, fields)
        set_data = template.encode()
        set_header = struct.pack("!HH", TEMPLATE_SET_ID, 4 + len(set_data))
        self._sets.append(set_header + set_data)
        return template_id

    def add_data_set(self, template_id: int, records: list[bytes]) -> None:
        """编码一个数据集。"""
        if not records:
            return
        payload = b"".join(records)
        set_header = struct.pack("!HH", template_id, 4 + len(payload))
        self._sets.append(set_header + payload)

    def build(self, export_time: int) -> bytes:
        """构建完整的 IPFIX 消息。"""
        self._sequence += 1
        sets_payload = b"".join(self._sets)
        # 补齐到 4 字节对齐
        padding = (4 - len(sets_payload) % 4) % 4
        if padding:
            sets_payload += b"\x00" * padding

        header = struct.pack(
            "!HHIIII",
            IPFIX_VERSION,
            16 + len(sets_payload),
            export_time,
            self._sequence,
            self.observation_domain_id,
        )
        self._sets.clear()
        return header + sets_payload

    @property
    def sequence(self) -> int:
        return self._sequence


# ── IPFIX 流导出器 ────────────────────────────────────

IPFIX_TEMPLATE_ID_FLOW = 256  # 标准流模板 ID


class IPFIXExporter:
    """IPFIX (NetFlow v10) 导出器。

    将 DPI 识别的流记录编码为 IPFIX 报文并发送到 Collector。
    """

    def __init__(
        self,
        collector_host: str = "127.0.0.1",
        collector_port: int = 4739,
        observation_domain_id: int = 1,
        export_interval: float = 10.0,
        mtu: int = 1400,
    ):
        self.collector_host = collector_host
        self.collector_port = collector_port
        self.observation_domain_id = observation_domain_id
        self.export_interval = export_interval
        self.mtu = mtu
        self._sock: Optional[socket.socket] = None
        self._msg = IPFIXMessage(observation_domain_id)
        self._template_sent = False
        self._enabled = False

    def start(self) -> None:
        """初始化 UDP 套接字。"""
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._enabled = True
            self._template_sent = False
            logger.info(
                "IPFIX 导出器已启动: %s:%d (ODID=%d)",
                self.collector_host, self.collector_port,
                self.observation_domain_id,
            )
        except OSError as e:
            logger.error("IPFIX 套接字创建失败: %s", e)

    def stop(self) -> None:
        """关闭 UDP 套接字。"""
        self._enabled = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        logger.info("IPFIX 导出器已停止")

    @property
    def is_running(self) -> bool:
        return self._enabled and self._sock is not None

    def _ensure_template(self) -> None:
        """发送模板（如果尚未发送）。"""
        if self._template_sent or not self._sock:
            return

        # 定义流模板字段
        # 使用常见 IPFIX 字段
        fields = [
            IPFIXTemplateField(IPFIX_FIELD["SOURCE_IPV4_ADDRESS"], 4),
            IPFIXTemplateField(IPFIX_FIELD["DESTINATION_IPV4_ADDRESS"], 4),
            IPFIXTemplateField(IPFIX_FIELD["PROTOCOL_IDENTIFIER"], 1),
            IPFIXTemplateField(IPFIX_FIELD["SOURCE_TRANSPORT_PORT"], 2),
            IPFIXTemplateField(IPFIX_FIELD["DESTINATION_TRANSPORT_PORT"], 2),
            IPFIXTemplateField(IPFIX_FIELD["PACKET_DELTA_COUNT"], 8),
            IPFIXTemplateField(IPFIX_FIELD["BYTE_DELTA_COUNT"], 8),
            IPFIXTemplateField(IPFIX_FIELD["FLOW_START_MILLISECONDS"], 8),
            IPFIXTemplateField(IPFIX_FIELD["FLOW_END_MILLISECONDS"], 8),
            IPFIXTemplateField(IPFIX_FIELD["TCP_CONTROL_BITS"], 1),
        ]

        self._msg.add_template_set(IPFIX_TEMPLATE_ID_FLOW, fields)
        msg_bytes = self._msg.build(int(time.time()))
        try:
            self._sock.sendto(msg_bytes, (self.collector_host, self.collector_port))
            self._template_sent = True
            logger.debug("IPFIX 模板已发送 (%d 字段)", len(fields))
        except OSError as e:
            logger.error("IPFIX 模板发送失败: %s", e)

    def export(self, flow: FlowRecord) -> None:
        """导出单条流记录为 IPFIX 数据记录。

        批量导出请使用 export_batch。
        """
        self.export_batch([flow])

    def _encode_flow_record(self, flow: FlowRecord) -> Optional[bytes]:
        """将 FlowRecord 编码为 IPFIX Data Record。"""
        try:
            buf = bytearray()

            # SOURCE_IPV4_ADDRESS (4 bytes)
            buf += socket.inet_aton(flow.src_ip)
            # DESTINATION_IPV4_ADDRESS (4 bytes)
            buf += socket.inet_aton(flow.dst_ip)
            # PROTOCOL_IDENTIFIER (1 byte)
            proto = 6 if flow.l4_proto == "tcp" else (17 if flow.l4_proto == "udp" else 0)
            buf += struct.pack("!B", proto)
            # SOURCE_TRANSPORT_PORT (2 bytes)
            buf += struct.pack("!H", flow.src_port)
            # DESTINATION_TRANSPORT_PORT (2 bytes)
            buf += struct.pack("!H", flow.dst_port)
            # PACKET_DELTA_COUNT (8 bytes)
            buf += struct.pack("!Q", flow.packets_sent + flow.packets_recv)
            # BYTE_DELTA_COUNT (8 bytes)
            buf += struct.pack("!Q", flow.bytes_sent + flow.bytes_recv)
            # FLOW_START_MILLISECONDS (8 bytes)
            start_ms = _encode_milliseconds(flow.timestamp.timestamp())
            buf += struct.pack("!Q", start_ms)
            # FLOW_END_MILLISECONDS (8 bytes)
            end_ms = start_ms + flow.duration_ms
            buf += struct.pack("!Q", end_ms)
            # TCP_CONTROL_BITS (1 byte) — 默认 0
            buf += struct.pack("!B", 0)

            return bytes(buf)
        except Exception as e:
            logger.debug("IPFIX 编码失败: %s", e)
            return None

    def export_batch(self, flows: list[FlowRecord]) -> int:
        """批量导出流记录。

        自动分片以适应 MTU。
        返回导出的记录数。
        """
        if not self._enabled or not self._sock:
            return 0

        self._ensure_template()
        if not self._template_sent:
            return 0

        records: list[bytes] = []
        for flow in flows:
            encoded = self._encode_flow_record(flow)
            if encoded:
                records.append(encoded)

        if not records:
            return 0

        now = int(time.time())
        sent = 0

        # 按 MTU 分片发送
        current_batch: list[bytes] = []
        current_size = 0

        for rec in records:
            if current_size + len(rec) > self.mtu - 100:  # 预留头部空间
                if current_batch:
                    self._msg.add_data_set(IPFIX_TEMPLATE_ID_FLOW, current_batch)
                    data = self._msg.build(now)
                    try:
                        self._sock.sendto(data, (self.collector_host, self.collector_port))
                        sent += len(current_batch)
                    except OSError as e:
                        logger.warning("IPFIX 发送失败: %s", e)
                    current_batch = []
                    current_size = 0
            current_batch.append(rec)
            current_size += len(rec)

        # 发送剩余
        if current_batch:
            self._msg.add_data_set(IPFIX_TEMPLATE_ID_FLOW, current_batch)
            data = self._msg.build(now)
            try:
                self._sock.sendto(data, (self.collector_host, self.collector_port))
                sent += len(current_batch)
            except OSError as e:
                logger.warning("IPFIX 发送失败: %s", e)

        if sent > 0:
            logger.debug("IPFIX 导出 %d 条流记录", sent)
        return sent
