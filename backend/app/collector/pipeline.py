"""采集流水线 — 连接 capture → DPI → flow manager → storage。

整合整个数据流：
  网卡/pcap → PacketCapture → DPIEngine → FlowManager → StorageBackend
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Optional

from app.collector.capture import PacketCapture, PcapReader
from app.collector.dpi import DPIEngine, create_dpi_engine
from app.collector.packet import ParsedPacket
from app.collector.pcap_writer import PcapWriter
from app.collector.tls_keylog import TLSKeyLogParser, create_keylog_parser
from app.export.ipfix import IPFIXExporter
from app.flow.manager import FlowManager
from app.geo.resolver import GeoIPResolver
from app.models.schemas import FlowRecord
from app.storage.base import StorageBackend
from app.storage.rrd_store import RRDStore
from app.utils.logger import get_logger

logger = get_logger("collector.pipeline")


class CapturePipeline:
    """采集流水线：协调抓包 → DPI → 流管理 → 存储 全流程。

    支持两种模式:
    - 在线模式: 从网卡实时抓包
    - 回放模式: 从 pcap 文件读取（开发调试）
    """

    def __init__(
        self,
        storage: StorageBackend,
        interface: str = "",
        pcap_file: str = "",
        dpi_lib_path: str = "libndpi.so",
        flush_interval: float = 5.0,
        stats_interval: float = 10.0,
        pcap_output_enabled: bool = False,
        pcap_output_dir: str = "./data/captures",
        pcap_max_file_size_mb: int = 100,
        pcap_max_file_count: int = 10,
        tls_keylog_file: str = "",
        tls_keylog_reload_interval: float = 5.0,
        geo_resolver: Optional[GeoIPResolver] = None,
        ipfix_enabled: bool = False,
        ipfix_host: str = "127.0.0.1",
        ipfix_port: int = 4739,
        ipfix_export_interval: float = 10.0,
    ):
        self.storage = storage
        self.interface = interface
        self.pcap_file = pcap_file
        self.dpi_lib_path = dpi_lib_path
        self.flush_interval = flush_interval
        self.stats_interval = stats_interval
        self.pcap_output_enabled = pcap_output_enabled
        self.tls_keylog_reload_interval = tls_keylog_reload_interval

        self.dpi: Optional[DPIEngine] = None
        self.geo_resolver = geo_resolver
        self.capture: Optional[PacketCapture] = None
        self._capture_tasks: list[asyncio.Task] = []
        self.pcap_reader: Optional[PcapReader] = None
        # 自动缓存写入器（数据缓存开关控制，写入缓存目录）
        self.cache_writer: Optional[PcapWriter] = None
        # 手动录制写入器（实时会话中的「PCAP 录制」按钮控制）
        self.recording_writer: Optional[PcapWriter] = None
        self._pcap_bpf_filter: str = ""
        self.tls_keylog: Optional[TLSKeyLogParser] = None
        self.flow_manager = FlowManager(idle_timeout=60)
        self.rrd_store = RRDStore()
        self.ipfix_exporter = IPFIXExporter(
            collector_host=ipfix_host,
            collector_port=ipfix_port,
            export_interval=ipfix_export_interval,
        ) if ipfix_enabled else None

        # pcap 输出配置（数据缓存：自动写入缓存目录）
        if pcap_output_enabled:
            self.cache_writer = PcapWriter(
                output_dir=pcap_output_dir,
                max_file_size=pcap_max_file_size_mb * 1024 * 1024,
                max_file_count=pcap_max_file_count,
            )

        # TLS Key Log
        if tls_keylog_file:
            self.tls_keylog = create_keylog_parser(tls_keylog_file)

        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._packets_processed = 0
        self._start_time: float = 0.0
        self._rrd_available = True
        # 按 flow key 累积的 L7 元数据（请求/响应分别存储）
        self._flow_meta: dict[str, dict[str, str]] = {}
        # 内存时序数据环形缓冲区 (360个点 × 10s = 1小时)
        self._time_series: list[dict] = []

    async def start(self) -> None:
        """启动采集流水线。"""
        if self._running:
            logger.warning("采集流水线已在运行")
            return

        if not self.interface and not self.pcap_file:
            logger.info("未配置采集接口，跳过采集启动")
            return

        self._running = True
        self._start_time = time.time()
        self._packets_processed = 0

        # 初始化 DPI 引擎
        logger.info("初始化 DPI 引擎...")
        self.dpi = create_dpi_engine(lib_path=self.dpi_lib_path)
        if self.dpi.is_available:
            logger.info("DPI 引擎: nDPI 模式")
        else:
            logger.info("DPI 引擎: 端口回退模式")

        # 初始化 RRDtool
        try:
            self.rrd_store.initialize()
            self._rrd_available = True
            logger.info("RRDtool 时序存储已初始化")
        except Exception as e:
            self._rrd_available = False
            logger.warning("RRDtool 初始化失败: %s (跳过)", e)

        # 启动任务
        if self.pcap_file:
            logger.info("采集模式: pcap 回放 (%s)", self.pcap_file)
            self._tasks.append(
                asyncio.create_task(self._replay_loop(), name="pcap-replay")
            )
        else:
            logger.info("采集模式: 在线抓包 (%s)", self.interface or "所有接口")
            self._tasks.append(
                asyncio.create_task(self._capture_loop(), name="capture")
            )

        # 初始化数据缓存写入器
        if self.cache_writer:
            self.cache_writer.open()
            logger.info("pcap 数据缓存已启用: %s", self.cache_writer.output_dir)

        # 启动定时刷流、统计、数据保留清理
        self._tasks.append(
            asyncio.create_task(self._flush_loop(), name="flush")
        )
        self._tasks.append(
            asyncio.create_task(self._stats_loop(), name="stats")
        )
        self._tasks.append(
            asyncio.create_task(self._retention_loop(), name="retention")
        )

        # 启动 TLS Key Log 热加载
        if self.tls_keylog and self.tls_keylog.is_available:
            self._tasks.append(
                asyncio.create_task(self._keylog_loop(), name="tls-keylog")
            )
            logger.info("TLS Key Log 热加载已启动 (共 %d 条密钥)", self.tls_keylog.key_count)

        # 启动 IPFIX 导出
        if self.ipfix_exporter:
            self.ipfix_exporter.start()
            self._tasks.append(
                asyncio.create_task(self._ipfix_loop(), name="ipfix")
            )
            logger.info("IPFIX 导出已启动: %s:%d",
                        self.ipfix_exporter.collector_host,
                        self.ipfix_exporter.collector_port)

        logger.info("采集流水线已启动")

    async def stop(self) -> None:
        """停止采集流水线。"""
        self._running = False

        # 停止抓包 — 兼容单网卡和多网卡
        if self.capture:
            self.capture.stop()
        for t in self._capture_tasks:
            t.cancel()
        self._capture_tasks.clear()

        # 关闭数据缓存与手动录制写入器
        if self.cache_writer:
            self.cache_writer.close()
        if self.recording_writer:
            self.recording_writer.close()

        # 停止 IPFIX 导出
        if self.ipfix_exporter:
            self.ipfix_exporter.stop()

        # 取消所有任务
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        # 刷出剩余流（DPI flow 已在 _flush_flows 中释放）
        await self._flush_flows()

        # 卸载 DPI
        if self.dpi:
            self.dpi.unload()

        logger.info(
            "采集流水线已停止 (处理 %d 包, 运行 %.1fs)",
            self._packets_processed,
            time.time() - self._start_time,
        )

    # ── PCAP 录制控制 ───────────────────────────────────

    def start_pcap_recording(
        self,
        output_dir: str = "./data/captures",
        max_file_size_mb: int = 100,
        max_file_count: int = 10,
        bpf_filter: str = "",
    ) -> bool:
        """动态开启 PCAP 文件录制。

        Args:
            bpf_filter: BPF 过滤表达式，仅匹配的包才会写入 pcap。
                       支持格式: "port 80", "port 443", "host 1.2.3.4",
                       "port 80 or port 443", "tcp", "udp"
        """
        if self.recording_writer is not None:
            logger.info("PCAP 录制已在运行")
            return True
        self._pcap_bpf_filter = bpf_filter
        if bpf_filter:
            logger.info("PCAP 录制 BPF 过滤: %s", bpf_filter)
        try:
            self.recording_writer = PcapWriter(
                output_dir=output_dir,
                max_file_size=max_file_size_mb * 1024 * 1024,
                max_file_count=max_file_count,
            )
            self.recording_writer.open()
            logger.info("PCAP 录制已开启 -> %s", output_dir)
            return True
        except Exception as e:
            logger.error("开启 PCAP 录制失败: %s", e)
            return False

    def stop_pcap_recording(self) -> bool:
        """动态关闭 PCAP 文件录制。"""
        if self.recording_writer is None:
            logger.info("PCAP 录制未运行")
            return True
        try:
            self.recording_writer.close()
            self.recording_writer = None
            self._pcap_bpf_filter = ""
            logger.info("PCAP 录制已关闭")
            return True
        except Exception as e:
            logger.error("关闭 PCAP 录制失败: %s", e)
            return False

    @property
    def pcap_recording(self) -> bool:
        """是否正在手动录制（与自动数据缓存无关）。"""
        return self.recording_writer is not None

    # ── BPF 过滤 ────────────────────────────────────────

    @staticmethod
    def _match_bpf(pkt: ParsedPacket, bpf_filter: str) -> bool:
        """简易 BPF 过滤匹配。"""
        expr = bpf_filter.strip().lower()
        # 按 or 分割
        parts = [p.strip() for p in expr.split("or")]
        for part in parts:
            if Pipeline._match_bpf_single(pkt, part):
                return True
        return False

    @staticmethod
    def _match_bpf_single(pkt: ParsedPacket, expr: str) -> bool:
        """匹配单个 BPF 条件。"""
        # 协议匹配
        if expr in ("tcp", "udp"):
            return pkt.l4_proto == expr
        # host 匹配
        if expr.startswith("host "):
            host = expr[5:].strip()
            return pkt.src_ip == host or pkt.dst_ip == host
        # port 匹配
        if expr.startswith("port "):
            port_str = expr[5:].strip()
            if port_str.isdigit():
                port = int(port_str)
                return pkt.src_port == port or pkt.dst_port == port
        # src port
        if expr.startswith("src port "):
            port_str = expr[9:].strip()
            if port_str.isdigit():
                return pkt.src_port == int(port_str)
        # dst port
        if expr.startswith("dst port "):
            port_str = expr[9:].strip()
            if port_str.isdigit():
                return pkt.dst_port == int(port_str)
        # src host
        if expr.startswith("src host "):
            return pkt.src_ip == expr[9:].strip()
        # dst host
        if expr.startswith("dst host "):
            return pkt.dst_ip == expr[9:].strip()
        # 不支持的表达式，默认放行
        return True

    # ── 处理单包 ────────────────────────────────────────

    async def _process_packet(self, pkt: ParsedPacket) -> None:
        """处理一个数据包：DPI → 流管理 → 存储 → pcap 输出。"""
        if pkt is None:
            return

        # DPI 检测（使用 per-flow 多包检测）
        flow_key = self.dpi.get_flow_key(pkt) if self.dpi else ""
        l7_proto = self.dpi.detect(pkt, flow_key=flow_key) if self.dpi else pkt.l7_proto

        # 获取协议分类（video / streaming / download / web 等）
        l7_category = self.dpi.detect_category(flow_key) if self.dpi and flow_key else ""

        # DEBUG: 记录 DPI 检测结果变化
        self._packets_processed += 1
        if self._packets_processed <= 5 or self._packets_processed % 1000 == 0:
            logger.debug(
                "包 #%d: %s:%d → %s:%d [%s] proto=%s",
                self._packets_processed,
                pkt.src_ip, pkt.src_port,
                pkt.dst_ip, pkt.dst_port,
                pkt.l4_proto, l7_proto,
            )

        # 确定流量方向: 根据规范化 flow key 判断
        # flow_key 格式: "ipA:portA-ipB:portB-proto" 其中 ipA < ipB
        # 如果 pkt.src_ip:src_port 等于 key 的前半部分, 则是出口(发送)
        # 否则是入口(接收)
        is_egress = True
        if flow_key:
            key_prefix = flow_key.rsplit("-", 1)[0]  # 去掉 proto
            parts = key_prefix.split("-")
            if len(parts) == 2:
                first_end = parts[0]  # "ipA:portA"
                src_end = f"{pkt.src_ip}:{pkt.src_port}"
                is_egress = (src_end == first_end)

        # L7 元数据提取：明文协议报文解析
        from app.collector.packet import (
            extract_dns_query, extract_host, extract_plaintext_content,
        )

        l7_meta = ""
        dst_host = ""
        if pkt.payload:
            # 提取目标主机/域名
            dst_host = extract_host(pkt.payload, l7_proto)

            content = extract_plaintext_content(pkt.payload)
            if content:
                if l7_proto == "dns":
                    domain = extract_dns_query(pkt.payload)
                    if domain:
                        l7_meta = f"🔍 DNS: {domain}\n{'-'*40}\n{content}"
                    else:
                        l7_meta = f"📦 DNS\n{'-'*40}\n{content}"
                else:
                    # 按方向累积: egress=请求, ingress=响应
                    if flow_key:
                        if flow_key not in self._flow_meta:
                            self._flow_meta[flow_key] = {}
                        direction = "request" if is_egress else "response"
                        # 累积所有包的明文内容（最多 8192 字节）
                        prev = self._flow_meta[flow_key].get(direction, "")
                        if prev:
                            # 追加新内容，payload 自带换行
                            combined = prev + content
                        else:
                            combined = content
                        if len(combined) > 8192:
                            combined = combined[:8192] + "\n... (截断)"
                        self._flow_meta[flow_key][direction] = combined
                        # 组装显示
                        meta = self._flow_meta[flow_key]
                        parts = []
                        if "request" in meta:
                            parts.append(f"▶ 请求\n{'─'*36}\n{meta['request']}")
                        if "response" in meta:
                            parts.append(f"◀ 响应\n{'─'*36}\n{meta['response']}")
                        label = l7_proto.upper()
                        l7_meta = f"📦 {label}\n{'='*36}\n" + "\n\n".join(parts)

        # TLS 增强: 检查是否有对应的密钥
        if not l7_meta and l7_proto in ("tls", "ssl") and self.tls_keylog and self.tls_keylog.is_available:
            client_random = self._extract_client_random(pkt)
            if client_random:
                key_entry = self.tls_keylog.lookup(client_random)
                if key_entry:
                    l7_meta = f"tls_key_available=true;client_random={client_random}"

        # GeoIP 查询: 解析目标 IP 的地理位置
        geo_country = ""
        geo_region = ""
        geo_city = ""
        geo_asn = 0
        geo_as_org = ""
        geo_lat = 0.0
        geo_lon = 0.0
        if self.geo_resolver and self.geo_resolver.is_available:
            target_ip = pkt.dst_ip if is_egress else pkt.src_ip
            geo_info = self.geo_resolver.lookup(target_ip)
            if geo_info:
                geo_country = geo_info.country_code
                geo_region = geo_info.region
                geo_city = geo_info.city
                geo_asn = geo_info.asn
                geo_as_org = geo_info.as_org
                geo_lat = geo_info.latitude
                geo_lon = geo_info.longitude

        # 构造 FlowRecord（区分方向）
        flow = FlowRecord(
            timestamp=pkt.timestamp,
            src_mac=pkt.src_mac,
            dst_mac=pkt.dst_mac,
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            src_port=pkt.src_port,
            dst_port=pkt.dst_port,
            l4_proto=pkt.l4_proto,
            l7_proto=l7_proto,
            bytes_sent=pkt.total_len if is_egress else 0,
            bytes_recv=pkt.total_len if not is_egress else 0,
            packets_sent=1 if is_egress else 0,
            packets_recv=1 if not is_egress else 0,
            l7_meta=l7_meta,
            l7_category=l7_category,
            duration_ms=0,
            interface=pkt.interface,
            dst_host=dst_host,
            dst_country=geo_country,
            dst_region=geo_region,
            dst_city=geo_city,
            dst_asn=geo_asn,
            dst_as_org=geo_as_org,
            dst_lat=geo_lat,
            dst_lon=geo_lon,
            pcap_file=(self.recording_writer or self.cache_writer).current_file
            if (self.recording_writer or self.cache_writer) else "",
        )

        # pcap 数据缓存输出（自动，无过滤）
        if self.cache_writer:
            self.cache_writer.write(pkt)
        # pcap 手动录制输出（支持 BPF 过滤）
        if self.recording_writer:
            if self._pcap_bpf_filter:
                if self._match_bpf(pkt, self._pcap_bpf_filter):
                    self.recording_writer.write(pkt)
            else:
                self.recording_writer.write(pkt)

        # 更新流管理器
        self.flow_manager.update(flow)

    def _extract_client_random(self, pkt: ParsedPacket) -> str:
        """从 TLS ClientHello 中提取 client_random (hex)。"""
        if pkt.l4_proto != "tcp" or not pkt.payload:
            return ""
        # TLS Record: content_type(1) + version(2) + length(2)
        # Handshake: handshake_type(1) + length(3) + version(2) + random(32)
        payload = pkt.payload
        # 跳过 TCP 选项
        # 简单检测: ClientHello 通常 > 40 字节且以 0x16 (Handshake) 开头
        if len(payload) < 6:
            return ""
        if payload[0] != 0x16:  # TLS Handshake Content Type
            return ""
        # 跳过 Record Header (5 bytes) + Handshake Header (4 bytes) + Version (2 bytes)
        # = 11 bytes offset to random
        if len(payload) < 43:
            return ""
        random_bytes = payload[11:43]
        if len(random_bytes) == 32:
            return random_bytes.hex()
        return ""

    # ── 在线抓包循环 ────────────────────────────────────

    async def _capture_loop(self) -> None:
        """在线抓包主循环 — 支持多网卡并发抓取。

        接口名用逗号分隔: "eth0,wlan0"
        """
        interfaces = [i.strip() for i in self.interface.split(",") if i.strip()]
        if not interfaces:
            logger.error("未指定抓包接口")
            return

        captures: list[PacketCapture] = []
        for iface in interfaces:
            try:
                cap = PacketCapture(
                    interface=iface,
                    snap_len=65535,
                    promisc=True,
                )
                captures.append(cap)
                logger.info("网卡 %s 已就绪", iface)
            except RuntimeError as e:
                logger.error("网卡 %s 初始化失败: %s", iface, e)

        if not captures:
            logger.error("所有网卡初始化失败，无法抓包")
            logger.error("需要 CAP_NET_RAW 权限，请以 root 运行或执行:")
            logger.error("  sudo setcap cap_net_raw,cap_net_admin=eip .venv/bin/python")
            return

        async def _read_one(cap: PacketCapture) -> None:
            """从单个网卡读取并处理数据包。"""
            try:
                async for pkt in cap.stream():
                    if not self._running:
                        break
                    await self._process_packet(pkt)
            except RuntimeError as e:
                logger.error("抓包失败 (%s): %s", cap.interface, e)
            except Exception as e:
                logger.error("抓包循环异常 (%s): %s", cap.interface, e)

        tasks = [asyncio.create_task(_read_one(c), name=f"capture-{cap.interface}")
                 for c in captures]
        self._capture_tasks = tasks

        try:
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error("多网卡抓包异常: %s", e)
        finally:
            for c in captures:
                try:
                    c.stop()
                except Exception:
                    pass

    # ── Pcap 回放循环 ───────────────────────────────────

    async def _replay_loop(self) -> None:
        """pcap 文件回放循环。"""
        try:
            reader = PcapReader(self.pcap_file)
            reader.open()

            last_ts: Optional[float] = None
            for pkt in reader:
                if not self._running:
                    break

                # 模拟实时时间间隔
                if last_ts is not None:
                    delay = (pkt.timestamp.timestamp() - last_ts)
                    if 0 < delay < 1.0:
                        await asyncio.sleep(delay)
                last_ts = pkt.timestamp.timestamp()

                await self._process_packet(pkt)

            reader.close()
            logger.info("pcap 回放完成")
        except FileNotFoundError:
            logger.error("pcap 文件不存在: %s", self.pcap_file)
        except Exception as e:
            logger.error("pcap 回放错误: %s", e)

    # ── 定时刷流 ────────────────────────────────────────

    async def _flush_loop(self) -> None:
        """定时刷出超时流和写入时序数据。"""
        while self._running:
            await asyncio.sleep(self.flush_interval)
            try:
                await self._flush_flows()
                await self._update_rrd()
            except Exception as e:
                logger.error("刷流出错: %s", e)

    async def _flush_flows(self) -> list[str]:
        """刷出超时流到存储后端，同时导出到 IPFIX，返回已刷出的 flow keys。"""
        expired = self.flow_manager.flush_idle()
        if not expired:
            return []

        # 为每条超时流检测安全风险
        if self.dpi and self.dpi.is_available:
            keys = self.flow_manager.get_last_flushed_keys()
            for flow_key, flow in zip(keys, expired):
                try:
                    risks = self.dpi.detect_risks(flow_key)
                    risk_score = self.dpi.get_risk_score(flow_key)
                    flow.risks = risks
                    flow.risk_score = risk_score
                except Exception:
                    pass
                # 释放 DPI flow 资源
                self.dpi.release_flow(flow_key)

        # IPFIX 导出已超时的流
        if self.ipfix_exporter and self.ipfix_exporter.is_running:
            self.ipfix_exporter.export_batch(expired)

        keys = self.flow_manager.get_last_flushed_keys() if not (self.dpi and self.dpi.is_available) else keys
        try:
            count = await self.storage.write_flows_batch(expired)
            if count > 0:
                logger.debug("刷出 %d 条流到存储", count)
                # 清理已刷出的流元数据缓存
                for k in keys:
                    self._flow_meta.pop(k, None)
        except Exception as e:
            logger.error("写入流失败: %s", e)
        return keys

    async def _update_rrd(self) -> None:
        """写入实时时序数据到 RRDtool（仅在可用时写入）。"""
        if not self._rrd_available:
            return
        overview = await self.storage.query_overview(time_range="5s")
        try:
            self.rrd_store.update(
                bps=overview.total_bps,
                pps=overview.total_pps,
                flow_rate=overview.active_flows,
            )
        except Exception as e:
            if self._rrd_available:
                self._rrd_available = False
                logger.warning("RRDtool 不可用，已禁用时序写入: %s", e)

    # ── TLS Key Log 热加载 ────────────────────────────

    async def _keylog_loop(self) -> None:
        """定时增量读取 SSLKEYLOGFILE。"""
        while self._running and self.tls_keylog:
            await asyncio.sleep(self.tls_keylog_reload_interval)
            try:
                new_keys = self.tls_keylog.reload()
                if new_keys > 0:
                    logger.info("TLS Key Log: 新增 %d 条密钥 (共 %d)",
                                new_keys, self.tls_keylog.key_count)
            except Exception as e:
                logger.error("TLS Key Log 加载错误: %s", e)

    # ── 统计日志 ────────────────────────────────────────

    async def _stats_loop(self) -> None:
        """定时打印处理统计，记录内存时序数据。"""
        prev_total_bytes = 0
        prev_total_packets = 0
        while self._running:
            await asyncio.sleep(self.stats_interval)
            elapsed = time.time() - self._start_time
            rate = self._packets_processed / elapsed if elapsed > 0 else 0
            logger.info(
                "[流水线统计] 处理 %d 包 | "
                "活跃流 %d | "
                "速率 %.1f pps | "
                "DPI: %s",
                self._packets_processed,
                self.flow_manager.active_count,
                rate,
                "nDPI" if (self.dpi and self.dpi.is_available) else "fallback",
            )

            # 记录内存时序数据
            now = int(time.time())
            active = self.flow_manager.get_active_flows()
            total_bytes = sum(f.bytes_sent + f.bytes_recv for f in active)
            total_packets = sum(f.packets_sent + f.packets_recv for f in active)
            delta_bytes = total_bytes - prev_total_bytes
            delta_packets = total_packets - prev_total_packets
            byte_rate = delta_bytes / self.stats_interval if delta_bytes >= 0 else 0
            bps = byte_rate * 8  # Bytes/s → bits/s
            pps = delta_packets / self.stats_interval if delta_packets >= 0 else 0
            prev_total_bytes = total_bytes
            prev_total_packets = total_packets

            self._time_series.append({
                "ts": now,
                "bps": round(bps, 1),
                "pps": round(pps, 1),
            })
            # 保留 360 个点 (10s × 360 = 1h)
            if len(self._time_series) > 360:
                self._time_series.pop(0)

    async def _retention_loop(self) -> None:
        """定时清理超过保留期的旧流记录（每小时检查一次）。"""
        from app.config import settings

        retention_days = settings.storage.retention_days
        logger.info("数据保留策略: 流记录保留 %d 天 (每小时检查清理)", retention_days)

        while self._running:
            await asyncio.sleep(3600)  # 每小时
            try:
                deleted = await self.storage.cleanup_old_flows(
                    retention_days=retention_days
                )
                if deleted > 0:
                    logger.info("数据保留: 已清理 %d 条过期流记录", deleted)
            except Exception as e:
                logger.warning("数据保留清理异常: %s", e)

    # ── IPFIX 导出循环 ─────────────────────────────────

    async def _ipfix_loop(self) -> None:
        """定时导出活跃流到 IPFIX Collector。"""
        if not self.ipfix_exporter:
            return
        interval = self.ipfix_exporter.export_interval
        while self._running:
            await asyncio.sleep(interval)
            try:
                if not self.ipfix_exporter.is_running:
                    continue
                flows = self.flow_manager.get_active_flows()
                if flows:
                    self.ipfix_exporter.export_batch(flows)
            except Exception as e:
                logger.error("IPFIX 导出循环异常: %s", e)

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packets_processed(self) -> int:
        return self._packets_processed

    @property
    def uptime_seconds(self) -> float:
        if not self._running or self._start_time == 0:
            return 0.0
        return time.time() - self._start_time

    def get_recent_time_series(
        self, max_points: int = 60
    ) -> list[dict]:
        """返回最近 N 个内存时序数据点。"""
        return list(self._time_series[-max_points:])
