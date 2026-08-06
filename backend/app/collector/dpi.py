"""nDPI 深度包检测引擎 — C 桥接库 + ctypes 绑定。

通过 C 桥接库 (libndpi_helper.so) 调用 nDPI，解决 ctypes 无法正确处理
struct-by-value 返回值的问题。桥接库返回干净的 uint16 协议 ID。

支持两种模式:
1. **nDPI 模式** — 加载 libndpi_helper.so，真正的 DPI 检测
2. **回退模式** — 桥接库不可用时，基于端口号猜测协议
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
from ctypes import c_char_p, c_int, c_uint16, c_uint64, c_void_p
from typing import Optional

from app.collector.packet import ParsedPacket
from app.utils.logger import get_logger

logger = get_logger("collector.dpi")

# ── nDPI 协议 ID 常量 ─────────────────────────────────
# 编号对应当前 nDPI v5.0 (src/include/ndpi_protocol_ids.h)，共 468 个协议 (0-467)。
NDPI_PROTOCOL_UNKNOWN = 0
NDPI_PROTOCOL_DNS = 5
NDPI_PROTOCOL_HTTP = 7
NDPI_PROTOCOL_DHCP = 18
NDPI_PROTOCOL_MYSQL = 20
NDPI_PROTOCOL_TLS = 91
NDPI_PROTOCOL_SSH = 92
NDPI_PROTOCOL_RTMP = 174
NDPI_PROTOCOL_QUIC = 188

# ── nDPI 风险严重级别 ─────────────────────────────────
RISK_SEVERITY_NAMES = ["low", "medium", "high", "severe", "critical", "emergency"]

# ── 重点关注的高危风险 ID (可按需扩展) ────────────────
HIGH_RISK_IDS = {
    5,   # NDPI_KNOWN_PROTOCOL_ON_NON_STANDARD_PORT
    6,   # NDPI_TLS_SELFSIGNED_CERTIFICATE
    7,   # NDPI_TLS_OBSOLETE_VERSION
    8,   # NDPI_TLS_WEAK_CIPHER
    9,   # NDPI_TLS_CERTIFICATE_EXPIRED
    10,  # NDPI_TLS_CERTIFICATE_MISMATCH
    16,  # NDPI_SUSPICIOUS_DGA_DOMAIN
    18,  # NDPI_SSH_OBSOLETE_CLIENT_VERSION_OR_CIPHER
    19,  # NDPI_SSH_OBSOLETE_SERVER_VERSION_OR_CIPHER
    20,  # NDPI_SMB_INSECURE_VERSION
    22,  # NDPI_UNSAFE_PROTOCOL
    24,  # NDPI_TLS_MISSING_SNI
    36,  # NDPI_CLEAR_TEXT_CREDENTIALS
    40,  # NDPI_POSSIBLE_EXPLOIT
    50,  # NDPI_TCP_ISSUES
    53,  # NDPI_MALWARE_HOST_CONTACTED
    56,  # NDPI_OBFUSCATED_TRAFFIC
    57,  # NDPI_SLOW_DOS
}

NDPI_PROTO_NAMES: dict[int, str] = {
    # ══ 重要 ════════════════════════════════════════════════════════════
    # 这仅是「C 桥接库不可用 / 名字获取失败」时的最后兜底映射。
    # 权威来源是 nDPI 的 ndpi_get_proto_name() —— 运行时共 468 个协议。
    # DPIEngine.load() 成功后会用桥接库动态生成完整正确的 self._proto_names，
    # 此静态表仅在桥接完全不可用时使用。
    # 编号对应当前 nDPI v5.0 (ndpi_protocol_ids.h)，切勿按旧版本编号。
    # ═══════════════════════════════════════════════════════════════════
    0: "unknown", 1: "ftp_control", 2: "pop3", 3: "smtp", 4: "imap",
    5: "dns", 6: "ipp", 7: "http", 8: "mdns", 9: "ntp",
    10: "netbios", 11: "nfs", 12: "ssdp", 13: "bgp", 14: "snmp",
    15: "xdmcp", 16: "smbv1", 17: "syslog", 18: "dhcp", 19: "postgresql",
    20: "mysql", 26: "ntop", 27: "coap", 30: "dtls", 37: "bittorrent",
    50: "rtsp", 60: "mongodb", 77: "telnet", 78: "stun", 79: "ipsec",
    87: "rtp", 88: "rdp", 89: "vnc", 91: "tls", 92: "ssh",
    93: "usenet", 94: "mgcp", 96: "tftp", 100: "sip", 112: "ldap",
    114: "mssql-tds", 115: "pptp", 119: "facebook", 120: "twitter",
    121: "dropbox", 130: "http_connect", 133: "netflix", 146: "radius",
    159: "openvpn", 163: "tor", 172: "socks", 174: "rtmp",
    176: "wikipedia", 182: "resp", 188: "quic", 196: "doh_dot",
    206: "wireguard", 349: "http2",
}


class DPIEngine:
    """nDPI 深度包检测引擎 (C 桥接库模式)。"""

    def __init__(self, lib_path: str = "libndpi_helper.so"):
        self.lib_path = lib_path
        self._helper: Optional[ctypes.CDLL] = None
        self._handle: int = 0
        self._available = False
        self._flow_map: dict[str, int] = {}
        # 流风险缓存: flow_key -> list[dict]
        self._risks: dict[str, list[dict]] = {}
        # 运行时从桥接库动态生成的完整协议名映射（兜底用，覆盖 nDPI 全部协议）
        self._proto_names: dict[int, str] = {}

    def _preload_ndpi_lib(self) -> None:
        """预加载 libndpi 依赖库，确保桥接库能解析其符号。

        桥接库 libndpi_helper.so 链接了 libndpi.so.5，而 nDPI 编译产物位于
        third/nDPI/src/lib/ 下、不在系统库搜索路径中。若不先加载该依赖，
        ctypes 加载桥接库会因找不到 libndpi.so.5 而失败 (OSError)，
        导致 DPI 静默降级为"端口回退"模式、完全无法做深度包检测。
        """
        _script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.normpath(
            os.path.join(_script_dir, "..", "..", "..")
        )
        candidates = [
            os.path.join(repo_root, "third", "nDPI", "src", "lib", "libndpi.so"),
            os.path.join(repo_root, "third", "nDPI", "src", "lib", "libndpi.so.5"),
            "/usr/local/lib/libndpi.so.5",
            "/usr/local/lib/libndpi.so",
            "/usr/lib/libndpi.so.5",
            "/usr/lib/x86_64-linux-gnu/libndpi.so.5",
        ]
        for cand in candidates:
            if os.path.exists(cand):
                try:
                    ctypes.CDLL(cand)
                    logger.info("已预加载 nDPI 依赖库: %s", cand)
                    return
                except OSError:
                    continue
        logger.warning("未找到 libndpi 依赖库，DPI 可能无法加载")

    def load(self) -> bool:
        """加载 nDPI 桥接库并初始化引擎。"""
        # 先加载 libndpi 依赖，再加载桥接库
        self._preload_ndpi_lib()

        _script_dir = os.path.dirname(os.path.abspath(__file__))
        search_paths = [
            os.path.join(_script_dir, "..", "..", "lib", "libndpi_helper.so"),
            os.path.join(_script_dir, "..", "..", "libndpi_helper.so"),
        ]
        for path in search_paths:
            norm = os.path.normpath(path)
            if not os.path.exists(norm):
                continue
            try:
                self._helper = ctypes.cdll.LoadLibrary(norm)
                logger.debug("nDPI 桥接库: %s", norm)
                break
            except OSError:
                continue
        if self._helper is None:
            logger.warning("nDPI 未找到，降级为端口回退")
            self._available = False
            return False

        self._setup_helper()
        self._handle = self._helper.ndpi_helper_init()
        if self._handle == 0:
            logger.error("nDPI 初始化失败")
            self._available = False
            return False
        logger.info("nDPI 引擎就绪 (handle=%d)", self._handle)
        self._available = True
        # 生成完整且正确的协议名映射（兜底用）
        self._proto_names = self._build_proto_name_map()
        return True

    def _setup_helper(self) -> None:
        h = self._helper
        h.ndpi_helper_init.restype = ctypes.c_int64
        h.ndpi_helper_destroy.argtypes = [ctypes.c_int64]
        h.ndpi_helper_destroy.restype = None
        h.ndpi_helper_create_flow.argtypes = [ctypes.c_int64]
        h.ndpi_helper_create_flow.restype = ctypes.c_int64
        h.ndpi_helper_free_flow.argtypes = [ctypes.c_int64]
        h.ndpi_helper_free_flow.restype = None
        h.ndpi_helper_process.argtypes = [ctypes.c_int64, ctypes.c_int64, c_void_p, c_uint16, c_uint64]
        h.ndpi_helper_process.restype = c_uint16
        h.ndpi_helper_giveup.argtypes = [ctypes.c_int64, ctypes.c_int64]
        h.ndpi_helper_giveup.restype = c_uint16
        h.ndpi_helper_proto_name.argtypes = [ctypes.c_int64, c_uint16]
        h.ndpi_helper_proto_name.restype = c_char_p
        h.ndpi_helper_category_id.argtypes = [ctypes.c_int64, ctypes.c_int64]
        h.ndpi_helper_category_id.restype = c_uint16
        h.ndpi_helper_category_name.argtypes = [ctypes.c_int64, ctypes.c_int64]
        h.ndpi_helper_category_name.restype = c_char_p
        # ── 风险检测 ──
        h.ndpi_helper_get_risk_bitmap.argtypes = [ctypes.c_int64]
        h.ndpi_helper_get_risk_bitmap.restype = c_uint64
        h.ndpi_helper_get_risk_info_count.argtypes = [ctypes.c_int64]
        h.ndpi_helper_get_risk_info_count.restype = c_int
        h.ndpi_helper_get_risk_info_at.argtypes = [
            ctypes.c_int64, ctypes.c_int,
            ctypes.POINTER(c_uint16), ctypes.c_char_p, ctypes.c_int,
        ]
        h.ndpi_helper_get_risk_info_at.restype = None
        h.ndpi_helper_risk_name.argtypes = [c_uint16]
        h.ndpi_helper_risk_name.restype = c_char_p
        h.ndpi_helper_risk_severity.argtypes = [c_uint16]
        h.ndpi_helper_risk_severity.restype = c_int
        h.ndpi_helper_severity_name.argtypes = [c_int]
        h.ndpi_helper_severity_name.restype = c_char_p

    def get_flow_key(self, packet: ParsedPacket) -> str:
        a = (packet.src_ip, packet.src_port)
        b = (packet.dst_ip, packet.dst_port)
        if a < b:
            return f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.l4_proto}"
        return f"{packet.dst_ip}:{packet.dst_port}-{packet.src_ip}:{packet.src_port}-{packet.l4_proto}"

    def get_or_create_flow(self, key: str) -> int:
        flow = self._flow_map.get(key)
        if flow is None:
            flow = self._helper.ndpi_helper_create_flow(self._handle)
            self._flow_map[key] = flow
        return flow

    def release_flow(self, key: str) -> None:
        flow = self._flow_map.pop(key, None)
        if flow:
            self._helper.ndpi_helper_free_flow(flow)
        self._risks.pop(key, None)

    def detect(self, packet: ParsedPacket, flow_key: str = "") -> str:
        """检测数据包的应用层协议。"""
        if not self._available or self._helper is None:
            return packet.l7_proto

        raw_data = packet.raw
        tick_ms = int(packet.timestamp.timestamp() * 1000)
        flow = self.get_or_create_flow(flow_key) if flow_key else self._helper.ndpi_helper_create_flow(self._handle)

        proto_id = self._helper.ndpi_helper_process(self._handle, flow, raw_data, len(raw_data), tick_ms)

        if proto_id == NDPI_PROTOCOL_UNKNOWN:
            try:
                proto_id = self._helper.ndpi_helper_giveup(self._handle, flow)
            except Exception:
                pass

        if proto_id != NDPI_PROTOCOL_UNKNOWN:
            try:
                name = self._helper.ndpi_helper_proto_name(self._handle, proto_id)
                if name:
                    return name.decode("utf-8", errors="replace")
            except Exception:
                pass
            # 优先用运行时动态映射（准确、覆盖全部协议），其次静态表（仅桥接不可用时）
            name = self._proto_names.get(proto_id) or NDPI_PROTO_NAMES.get(proto_id)
            if name:
                return name

        if not flow_key and flow:
            self._helper.ndpi_helper_free_flow(flow)
        return packet.l7_proto

    def _build_proto_name_map(self) -> dict[int, str]:
        """从 nDPI 桥接库动态生成完整协议名映射（覆盖全部 468 个协议）。

        静态 NDPI_PROTO_NAMES 的编号可能随 nDPI 版本变化而失效，
        因此只要桥接可用，就据此生成最新最全的映射，作为协议名获取失败时的兜底。
        返回值的 key 为协议 ID，value 为 nDPI 返回的原始名字。
        """
        names: dict[int, str] = {}
        try:
            for pid in range(512):
                raw = self._helper.ndpi_helper_proto_name(self._handle, pid)
                if not raw:
                    continue
                name = raw.decode("utf-8", errors="replace").strip()
                if name and name.lower() not in ("", "unknown"):
                    names[pid] = name
        except Exception as e:
            logger.warning("生成协议名映射失败，使用静态 NDPI_PROTO_NAMES: %s", e)
            return dict(NDPI_PROTO_NAMES)
        return names

    def detect_category(self, flow_key: str) -> str:
        """获取已检测流的协议分类（如 video, streaming, download 等）。"""
        if not self._available or self._helper is None:
            return ""
        flow = self._flow_map.get(flow_key)
        if flow is None:
            return ""
        try:
            name = self._helper.ndpi_helper_category_name(self._handle, flow)
            if name:
                return name.decode("utf-8", errors="replace").lower()
        except Exception:
            pass
        return ""

    def detect_risks(self, flow_key: str) -> list[dict]:
        """检测流的安全风险，返回风险列表。

        每个风险包含:
          - id: int (ndpi_risk_enum)
          - name: str (如 "TLS Self-Signed Certificate")
          - severity: int (0=low .. 5=emergency)
          - severity_name: str
          - info: str (详细描述, 可能为空)
        """
        if not self._available or self._helper is None:
            return []
        flow = self._flow_map.get(flow_key)
        if flow is None:
            return []

        # 避免重复检测
        cached = self._risks.get(flow_key)
        if cached is not None:
            return cached

        try:
            bitmap = self._helper.ndpi_helper_get_risk_bitmap(flow)
            if bitmap == 0:
                self._risks[flow_key] = []
                return []

            risks = []
            # 获取详细风险信息
            count = self._helper.ndpi_helper_get_risk_info_count(flow)
            info_buf = ctypes.create_string_buffer(512)

            for i in range(count):
                risk_id = c_uint16(0)
                self._helper.ndpi_helper_get_risk_info_at(
                    flow, i,
                    ctypes.byref(risk_id), info_buf, ctypes.c_int(len(info_buf)),
                )
                rid = risk_id.value
                name = self._helper.ndpi_helper_risk_name(rid)
                sev = self._helper.ndpi_helper_risk_severity(rid)
                sev_name = self._helper.ndpi_helper_severity_name(sev)
                risks.append({
                    "id": rid,
                    "name": name.decode("utf-8", errors="replace") if name else f"risk_{rid}",
                    "severity": sev,
                    "severity_name": sev_name.decode("utf-8", errors="replace") if sev_name else "unknown",
                    "info": info_buf.value.decode("utf-8", errors="replace") if info_buf.value else "",
                })

            # 如果 risk_infos 没有覆盖所有 bit，补全剩余的
            detected_ids = {r["id"] for r in risks}
            for bit in range(64):
                if bitmap & (1 << bit):
                    if bit not in detected_ids and bit < 64:
                        name = self._helper.ndpi_helper_risk_name(bit)
                        sev = self._helper.ndpi_helper_risk_severity(bit)
                        sev_name = self._helper.ndpi_helper_severity_name(sev)
                        risks.append({
                            "id": bit,
                            "name": name.decode("utf-8", errors="replace") if name else f"risk_{bit}",
                            "severity": sev,
                            "severity_name": sev_name.decode("utf-8", errors="replace") if sev_name else "unknown",
                            "info": "",
                        })

            self._risks[flow_key] = risks
            return risks
        except Exception as e:
            logger.debug("风险检测异常: %s", e)
            return []

    def get_risk_score(self, flow_key: str) -> int:
        """计算流的安全风险总分 (0-1000)。"""
        risks = self.detect_risks(flow_key)
        if not risks:
            return 0
        # 按严重级别加权: low=1, medium=10, high=50, severe=100, critical=200, emergency=500
        weight_map = {0: 1, 1: 10, 2: 50, 3: 100, 4: 200, 5: 500}
        return sum(weight_map.get(r["severity"], 1) for r in risks)

    def flush_all_flows(self) -> list[tuple[str, str, list[dict], int]]:
        results = []
        for key, flow in list(self._flow_map.items()):
            try:
                pid = self._helper.ndpi_helper_giveup(self._handle, flow)
                name = ""
                if pid:
                    n = self._helper.ndpi_helper_proto_name(self._handle, pid)
                    name = n.decode() if n else (self._proto_names.get(pid) or NDPI_PROTO_NAMES.get(pid, ""))
                # 检测风险
                risks = self.detect_risks(key)
                risk_score = self.get_risk_score(key)
                results.append((key, name, risks, risk_score))
            except Exception:
                results.append((key, "", [], 0))
        return results

    def unload(self) -> None:
        for key in list(self._flow_map.keys()):
            self.release_flow(key)
        self._flow_map.clear()
        if self._handle and self._helper:
            self._helper.ndpi_helper_destroy(self._handle)
        self._helper = None
        self._handle = 0
        self._available = False

    @property
    def is_available(self) -> bool:
        return self._available


def create_dpi_engine(lib_path: str = "libndpi_helper.so") -> DPIEngine:
    engine = DPIEngine(lib_path=lib_path)
    engine.load()
    return engine
