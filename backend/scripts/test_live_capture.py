#!/usr/bin/env python3
"""向实际网口注入协议测试包，验证 FluxEye 的抓取、解析、统计与时间。

注入方式：AF_PACKET 原始套接字向 lo 网口发送合成报文（复用 tests/test_protocols.py
的报文构建器）。lo 回环会将该帧投递 2 次（发送路径 + 回环接收路径），因此
FluxEye 统计到的包/字节数约为注入帧的 2 倍——这是 lo 注入方法的固有特性，
并非抓包缺陷（真实走 IP 栈的流量只计一次）。

验证内容：
  1. 解析正确性：l7_proto / dst_host / l7_meta
  2. 流量统计：bytes_sent / bytes_recv / packets_sent / packets_recv
  3. 时间：first_seen（出现时间）/ last_seen（结束时间）/ duration_ms（时长）

用法:
    python scripts/test_live_capture.py                 # 注入全部协议并验证
    python scripts/test_live_capture.py --interface eth0 # 指定注入网口
    python scripts/test_live_capture.py --check-only     # 仅校验上次注入的流量
    python scripts/test_live_capture.py --wait-flush     # 校验后等待刷库并查 SQLite
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time
import urllib.request
from datetime import datetime, timezone

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND_DIR)

from tests.test_protocols import (  # noqa: E402
    build_dhcp_discover,
    build_dns_query,
    build_dns_response,
    build_http_get,
    build_ntp_packet,
    build_quic_initial,
    build_socks5_connect,
    build_ssh_banner,
    build_tcp_packet,
    build_tls_clienthello,
    build_udp_packet,
)

API = "http://127.0.0.1:8011/api/v1"
# TEST-NET 网段用于标记测试流量，避免与真实流量混淆
TEST_PREFIX = "192.0.2."


# ── API 辅助 ──────────────────────────────────────────

def api_get(path: str) -> dict | list:
    with urllib.request.urlopen(f"{API}{path}", timeout=10) as r:
        return json.loads(r.read().decode())


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── 注入 ──────────────────────────────────────────────

def inject_frame(frame: bytes, interface: str) -> int:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        s.bind((interface, 0))
        return s.send(frame)
    finally:
        s.close()


# ── 测试用例 ──────────────────────────────────────────

def build_cases():
    """返回注入用例列表：每个含名称、预期解析结果、帧构造函数。

    每次运行使用随机源端口基址，避免与上次运行产生相同 flow key，
    从而确保 first_seen/duration 反映本次注入的真实时间。
    """
    base = random.randint(20000, 45000)  # 随机端口基址，保证全新流

    def port(i):
        return base + i

    return [
        {
            "name": "HTTP",
            "src_ip": "192.0.2.10",
            "expected_l7": "http",
            "expect_dst_host": "www.test-http.com",
            "expect_meta": "GET /index.html HTTP/1.1",
            "frames": [
                build_tcp_packet("192.0.2.10", "93.184.216.34", port(1), 80,
                                 build_http_get("www.test-http.com")),
            ],
        },
        {
            "name": "HTTPS/TLS",
            "src_ip": "192.0.2.11",
            "expected_l7": "tls",
            "expect_dst_host": "api.test-tls.com",
            "expect_meta": "",
            "frames": [
                build_tcp_packet("192.0.2.11", "93.184.216.34", port(2), 443,
                                 build_tls_clienthello("api.test-tls.com")),
            ],
        },
        {
            "name": "DNS(查询+响应)",
            "src_ip": "192.0.2.12",
            "expected_l7": "dns",
            "expect_meta": "DNS 请求: www.test-dns.com (A)",
            "expect_meta_after": "www.test-dns.com -> 93.184.216.34 (A)",
            "frames": [
                build_udp_packet("192.0.2.12", "8.8.8.8", port(3), 53,
                                 build_dns_query("www.test-dns.com", qid=0x1111)),
                build_udp_packet("8.8.8.8", "192.0.2.12", 53, port(3),
                                 build_dns_response("www.test-dns.com", "93.184.216.34", qid=0x1111)),
            ],
        },
        {
            "name": "NTP",
            "src_ip": "192.0.2.13",
            "expected_l7": "ntp",
            "frames": [
                build_udp_packet("192.0.2.13", "185.125.190.57", port(4), 123,
                                 build_ntp_packet()),
            ],
        },
        {
            "name": "SSH",
            "src_ip": "192.0.2.14",
            "expected_l7": "ssh",
            "frames": [
                build_tcp_packet("192.0.2.14", "203.0.113.9", port(5), 22,
                                 build_ssh_banner()),
            ],
        },
        {
            "name": "QUIC",
            "src_ip": "192.0.2.15",
            "expected_l7": ("google", "quic"),  # nDPI 解析内层 Google 子协议
            "frames": [
                build_udp_packet("192.0.2.15", "8.8.8.8", port(6), 4433,
                                 build_quic_initial()),
            ],
        },
        {
            "name": "SOCKS5",
            "src_ip": "192.0.2.16",
            "expected_l7": "socks",
            "expect_dst_host": "proxy.test-socks.com",
            "frames": [
                build_tcp_packet("192.0.2.16", "203.0.113.9", port(7), 1080,
                                 build_socks5_connect("proxy.test-socks.com")),
            ],
        },
        {
            "name": "HTTP/2",
            "src_ip": "192.0.2.17",
            "expected_l7": "http2",
            "frames": [
                build_tcp_packet("192.0.2.17", "93.184.216.34", port(8), 80,
                                 b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00" * 9),
            ],
        },
        {
            "name": "DHCP",
            "src_ip": "0.0.0.0",  # DHCP 无源 IP，用目标 255.255.255.255 匹配
            "expected_l7": "dhcp",
            "match_dst_ip": "255.255.255.255",
            "frames": [
                build_udp_packet("0.0.0.0", "255.255.255.255", 68, 67,
                                 build_dhcp_discover()),
            ],
        },
    ]


# ── 注入执行 ──────────────────────────────────────────

def run_injection(cases, interface: str, dns_gap: float = 1.5):
    """按序注入所有用例的帧，DNS 的请求/响应之间间隔 dns_gap 秒以验证时长。"""
    results = []
    for case in cases:
        frames = case["frames"]
        # DNS 双包用例：请求与响应间隔 dns_gap 秒
        if len(frames) > 1:
            t0 = time.time()
            inject_frame(frames[0], interface)
            results.append({"case": case, "injected_at": t0, "packet_count": len(frames)})
            time.sleep(dns_gap)
            inject_frame(frames[1], interface)
        else:
            t0 = time.time()
            inject_frame(frames[0], interface)
            results.append({"case": case, "injected_at": t0, "packet_count": len(frames)})
        time.sleep(0.3)  # 相邻用例间隔，避免时间戳重叠
    return results


# ── 校验 ──────────────────────────────────────────────

def _page_items(resp) -> list:
    """提取分页响应中的 items（conversations 返回 Page 对象）。"""
    if isinstance(resp, dict):
        return resp.get("items", [])
    return resp if isinstance(resp, list) else []


def _match_flow(flows: list[dict], case: dict) -> dict | None:
    """按 src_ip（DHCP 用 dst_ip）匹配用例对应的流。"""
    if "match_dst_ip" in case:
        return next((f for f in flows if f.get("dst_ip") == case["match_dst_ip"]), None)
    return next((f for f in flows if f.get("src_ip") == case["src_ip"]), None)


def verify(cases, injected, flows_by_src, check_time: bool = True) -> list[dict]:
    """逐用例校验，返回结果行。"""
    report = []
    for item in injected:
        case = item["case"]
        flow = _match_flow(flows_by_src, case)
        name = case["name"]
        if flow is None:
            report.append({"name": name, "ok": False, "issues": ["未捕获到流"], "flow": None})
            continue

        issues = []
        # 1. 解析正确性
        expected = case["expected_l7"]
        actual = (flow.get("l7_proto") or "").lower()
        if isinstance(expected, tuple):
            ok_proto = actual in expected
        else:
            ok_proto = actual == expected
        if not ok_proto:
            issues.append(f"l7_proto 期望 {expected} 实际 {actual}")

        if "expect_dst_host" in case:
            dh = flow.get("dst_host") or ""
            if dh != case["expect_dst_host"]:
                issues.append(f"dst_host 期望 {case['expect_dst_host']} 实际 {dh}")
        if "expect_meta" in case and case["expect_meta"]:
            meta = flow.get("l7_meta") or ""
            if case["expect_meta"] not in meta:
                issues.append(f"l7_meta 缺少 '{case['expect_meta']}'")
        if "expect_meta_after" in case:
            meta = flow.get("l7_meta") or ""
            if case["expect_meta_after"] not in meta:
                issues.append(f"l7_meta 缺少响应内容 '{case['expect_meta_after']}'")

        # 2. 流量统计（lo 注入会重复计数约 2 倍）
        pkt = flow.get("packets_sent", 0) + flow.get("packets_recv", 0)
        n_injected = item["packet_count"]
        if pkt < n_injected:
            issues.append(f"包数 {pkt} 少于注入 {n_injected}")

        # 3. 时间
        if check_time:
            t_inj = item["injected_at"]
            try:
                t_first = datetime.fromisoformat(flow["first_seen"].replace("Z", "+00:00"))
                t_last = datetime.fromisoformat(flow["last_seen"].replace("Z", "+00:00"))
            except Exception:
                issues.append("first_seen/last_seen 解析失败")
            else:
                dt_first = (t_first.timestamp() - t_inj)
                if not (-2 <= dt_first <= 10):
                    issues.append(f"first_seen 距注入 {dt_first:.1f}s 偏差过大")
                # DNS 双包用例：时长应至少覆盖 dns_gap
                if len(case["frames"]) > 1:
                    dur_ms = flow.get("duration_ms", 0)
                    if dur_ms < 1000:
                        issues.append(f"duration_ms={dur_ms} 应覆盖请求+响应间隔")

        report.append({
            "name": name,
            "ok": not issues,
            "issues": issues,
            "flow": {
                "l7_proto": flow.get("l7_proto"),
                "l4_proto": flow.get("l4_proto"),
                "src_ip": flow.get("src_ip"),
                "dst_ip": flow.get("dst_ip"),
                "src_port": flow.get("src_port"),
                "dst_port": flow.get("dst_port"),
                "dst_host": flow.get("dst_host"),
                "bytes_sent": flow.get("bytes_sent"),
                "bytes_recv": flow.get("bytes_recv"),
                "packets_sent": flow.get("packets_sent"),
                "packets_recv": flow.get("packets_recv"),
                "first_seen": flow.get("first_seen"),
                "last_seen": flow.get("last_seen"),
                "duration_ms": flow.get("duration_ms"),
                "l7_meta": flow.get("l7_meta"),
            },
        })
    return report


def print_report(report: list[dict]) -> int:
    passed = 0
    for row in report:
        status = "✅" if row["ok"] else "❌"
        print(f"\n{status} {row['name']}")
        f = row["flow"]
        if f:
            print(f"   协议: {f['l4_proto']}/{f['l7_proto']}  "
                  f"{f['src_ip']}:{f['src_port']} → {f['dst_ip']}:{f['dst_port']}")
            if f.get("dst_host"):
                print(f"   目标: {f['dst_host']}")
            print(f"   流量: ↑{f['bytes_sent']}B/{f['packets_sent']}包  "
                  f"↓{f['bytes_recv']}B/{f['packets_recv']}包  "
                  f"总{ (f['bytes_sent'] or 0) + (f['bytes_recv'] or 0) }B")
            print(f"   时间: 出现 {f['first_seen']}  →  结束 {f['last_seen']}  "
                  f"时长 {f['duration_ms']}ms")
            meta = (f.get("l7_meta") or "").replace("\r\n", "\\r\\n")
            if meta:
                print(f"   内容: {meta[:120]}")
        if row["issues"]:
            for iss in row["issues"]:
                print(f"   ⚠ {iss}")
        else:
            passed += 1
    print(f"\n======== 结果: {passed}/{len(report)} 通过 ========")
    return 0 if passed == len(report) else 1


# ── 主流程 ────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="FluxEye 实际网口发包验证")
    ap.add_argument("--interface", default="lo", help="注入网口 (默认 lo)")
    ap.add_argument("--check-only", action="store_true", help="不注入，仅校验已有测试流量")
    ap.add_argument("--wait-flush", action="store_true",
                    help="校验实时流后等待流刷入 SQLite 再校验一次")
    ap.add_argument("--dns-gap", type=float, default=1.5, help="DNS 请求/响应间隔秒")
    args = ap.parse_args()

    cases = build_cases()

    if not args.check_only:
        print(f"向接口 {args.interface} 注入 {len(cases)} 组协议测试包 ...")
        injected = run_injection(cases, args.interface, dns_gap=args.dns_gap)
    else:
        injected = [{"case": c, "injected_at": time.time(), "packet_count": len(c["frames"])}
                    for c in cases]

    # 等待 FluxEye 处理
    print("等待 FluxEye 处理 (2s) ...")
    time.sleep(2)

    flows = api_get("/traffic/live")
    report = verify(cases, injected, flows, check_time=not args.check_only)
    rc = print_report(report)

    if args.wait_flush and not args.check_only:
        print(f"\n等待流空闲刷入 SQLite (65s) ...")
        time.sleep(65)
        # 从 conversations (SQLite) 重新校验
        db_flows = []
        for case in cases:
            if "match_dst_ip" in case:
                resp = api_get(f"/traffic/conversations?size=50&dst_ip={case['match_dst_ip']}")
                db_flows += _page_items(resp)
            else:
                resp = api_get(f"/traffic/conversations?size=50&src_ip={case['src_ip']}")
                db_flows += _page_items(resp)
        report2 = verify(cases, injected, db_flows, check_time=False)
        print("\n===== SQLite 持久化校验 =====")
        rc = print_report(report2) or rc

    return rc


if __name__ == "__main__":
    sys.exit(main())
