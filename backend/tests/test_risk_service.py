"""安全风险检测 & 服务映射单元测试。"""

from __future__ import annotations

import pytest

from app.storage.sqlite_store import SQLiteStore


class TestServiceMapping:
    """_SERVICE_MAP 域名→服务映射测试。"""

    def test_google_mapping(self):
        assert SQLiteStore._SERVICE_MAP.get("google.com") == "Google"
        assert SQLiteStore._SERVICE_MAP.get("youtube.com") == "YouTube"
        assert SQLiteStore._SERVICE_MAP.get("gmail.com") == "Gmail"

    def test_chinese_mapping(self):
        assert SQLiteStore._SERVICE_MAP.get("qq.com") == "QQ"
        assert SQLiteStore._SERVICE_MAP.get("weixin.qq.com") == "微信"
        assert SQLiteStore._SERVICE_MAP.get("douyin.com") == "抖音"
        assert SQLiteStore._SERVICE_MAP.get("taobao.com") == "淘宝"

    def test_ai_mapping(self):
        assert SQLiteStore._SERVICE_MAP.get("openai.com") == "OpenAI/ChatGPT"
        assert SQLiteStore._SERVICE_MAP.get("deepseek.com") == "DeepSeek"
        assert SQLiteStore._SERVICE_MAP.get("githubcopilot.com") == "GitHub Copilot"

    def test_social_mapping(self):
        assert SQLiteStore._SERVICE_MAP.get("facebook.com") == "Facebook"
        assert SQLiteStore._SERVICE_MAP.get("twitter.com") == "Twitter/X"
        assert SQLiteStore._SERVICE_MAP.get("telegram.org") == "Telegram"

    def test_map_service_known_proto(self):
        """非泛型协议名直接返回（如 YouTube）。"""
        result = SQLiteStore._map_service("youtube", "")
        assert result == "YOUTUBE"

    def test_map_service_known_proto_lower(self):
        """nDPI 返回的小写协议名也应直接识别。"""
        result = SQLiteStore._map_service("netflix", "")
        assert result == "NETFLIX"

    def test_map_service_tls_fallback(self):
        """TLS 协议回退到域名匹配。"""
        result = SQLiteStore._map_service("tls", "google.com")
        assert result == "Google"

    def test_map_service_socks_fallback(self):
        """SOCKS 协议通过域名匹配服务。"""
        result = SQLiteStore._map_service("socks", "api.deepseek.com")
        assert result == "DeepSeek"

    def test_map_service_unknown_domain(self):
        """未知域名按主域名 capitalize。"""
        result = SQLiteStore._map_service("tls", "some.random-site.com")
        assert result == "Random-site.com"

    def test_map_service_no_host(self):
        """无 host 时返回协议名。"""
        result = SQLiteStore._map_service("socks", "")
        assert result == "SOCKS"

    def test_map_service_ntp_no_match(self):
        """NTP 等基础协议直接返回，忽略域名。"""
        result = SQLiteStore._map_service("ntp", "pool.ntp.org")
        assert result == "NTP"
        # 即使带任何域名也返回协议名
        assert SQLiteStore._map_service("ntp", "time.google.com") == "NTP"

    def test_map_service_subdomain_match(self):
        """子域名应匹配父域名映射。"""
        result = SQLiteStore._map_service("tls", "drive.google.com")
        assert result == "Google"

    def test_map_service_chinese_platforms(self):
        """中国平台映射验证。"""
        assert SQLiteStore._map_service("tls", "bilibili.com") == "B站"
        assert SQLiteStore._map_service("tls", "zhihu.com") == "知乎"
        assert SQLiteStore._map_service("tls", "xiaohongshu.com") == "小红书"
        assert SQLiteStore._map_service("tls", "meituan.com") == "美团"
        assert SQLiteStore._map_service("tls", "pinduoduo.com") == "拼多多"

    def test_map_service_banks(self):
        """银行域名映射验证。"""
        assert SQLiteStore._map_service("tls", "cmbchina.com") == "招商银行"
        assert SQLiteStore._map_service("tls", "icbc.com.cn") == "工商银行"
        assert SQLiteStore._map_service("tls", "ccb.com") == "建设银行"

    def test_map_service_appliances(self):
        """家电品牌映射验证。"""
        assert SQLiteStore._map_service("tls", "midea.com") == "美的"
        assert SQLiteStore._map_service("tls", "haier.com") == "海尔"
        assert SQLiteStore._map_service("tls", "gree.com.cn") == "格力"

    def test_map_service_cloud(self):
        """云服务映射验证。"""
        result = SQLiteStore._map_service("tls", "s3.amazonaws.com")
        # Could match "AWS" via "amazonaws.com" or "AWS S3" via "s3.amazonaws.com"
        assert "AWS" in result

    def test_service_map_has_300_plus_entries(self):
        """验证映射表条目>300。"""
        assert len(SQLiteStore._SERVICE_MAP) >= 300


class TestMapServiceEdgeCases:
    """_map_service 边界情况测试。"""

    def test_empty_proto_and_host(self):
        assert SQLiteStore._map_service("", "") == "UNKNOWN"

    def test_dhcp_protocol(self):
        """DHCP 等基础协议直接使用。"""
        result = SQLiteStore._map_service("dhcp", "")
        assert result == "DHCP"

    def test_ip_as_host(self):
        """IP 地址作为 host 应返回原始 IP。"""
        result = SQLiteStore._map_service("tls", "1.2.3.4")
        assert result == "1.2.3.4"

    def test_local_domain(self):
        result = SQLiteStore._map_service("dns", "localhost")
        assert result is not None
