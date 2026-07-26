"""MAC OUI 厂商查询单元测试。"""

from __future__ import annotations

from app.geo.mac_vendor import (
    lookup_vendor,
    vendor_alias,
    _normalize_mac,
    _oui_prefix,
)


class TestMacNormalize:
    """MAC 地址标准化测试。"""

    def test_colon_format(self):
        assert _normalize_mac("e4:f2:7c:11:22:33") == "E4F27C112233"

    def test_hyphen_format(self):
        assert _normalize_mac("e4-f2-7c-11-22-33") == "E4F27C112233"

    def test_no_separator(self):
        assert _normalize_mac("e4f27c112233") == "E4F27C112233"

    def test_uppercase(self):
        assert _normalize_mac("E4:F2:7C:11:22:33") == "E4F27C112233"


class TestOuiPrefix:
    """OUI 前缀提取测试。"""

    def test_oui24_prefix(self):
        prefixes = _oui_prefix("e4:f2:7c:11:22:33")
        assert "E4F27C" in prefixes
        assert "E4F27C1" in prefixes
        assert "E4F27C112" in prefixes

    def test_short_mac(self):
        prefixes = _oui_prefix("e4:f2")
        assert prefixes == []


class TestLookupVendor:
    """厂商查询测试。"""

    def test_known_cisco(self):
        assert lookup_vendor("e8:0a:b9:00:00:01") == "Cisco Systems, Inc"

    def test_known_juniper(self):
        assert lookup_vendor("e4:f2:7c:11:22:33") == "Juniper Networks"

    def test_known_huawei(self):
        assert lookup_vendor("e0:06:30:00:00:01") == "HUAWEI TECHNOLOGIES CO.,LTD"

    def test_known_apple(self):
        assert lookup_vendor("e8:80:2e:00:00:01") == "Apple, Inc."

    def test_unknown_vendor(self):
        assert lookup_vendor("ff:ff:ff:ff:ff:ff") == "Unknown"

    def test_empty_mac(self):
        assert lookup_vendor("") == "Unknown"

    def test_mac_with_dot_notation(self):
        assert lookup_vendor("e4f2.7c11.2233") == "Juniper Networks"


class TestVendorAlias:
    """厂商别名测试。"""

    def test_cisco_alias(self):
        assert vendor_alias("Cisco Systems, Inc") == "Cisco"

    def test_huawei_alias(self):
        assert vendor_alias("HUAWEI TECHNOLOGIES CO.,LTD") == "华为"

    def test_apple_alias(self):
        assert vendor_alias("Apple, Inc.") == "Apple"

    def test_unknown_stays(self):
        assert vendor_alias("Some Unknown Corp") == "Some Unknown Corp"
