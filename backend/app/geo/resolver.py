"""GeoIP 解析器 — 使用 geoip2 库查询 MaxMind GeoLite2 数据库。

支持:
- 城市级定位 (GeoLite2-City.mmdb)
- ASN 查询 (GeoLite2-ASN.mmdb)
- 内网 IP 自动跳过
- 数据库缺失时静默降级
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.utils.logger import get_logger

logger = get_logger("geo.resolver")


@dataclass
class GeoInfo:
    """IP 地理位置信息。"""
    country_code: str = ""
    country_name: str = ""
    region: str = ""       # 省/州
    city: str = ""
    asn: int = 0
    as_org: str = ""
    latitude: float = 0.0
    longitude: float = 0.0


# 内网 / 保留地址段 — 无需查询 GeoIP
_PRIVATE_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
]


def _is_private(ip_str: str) -> bool:
    """判断是否为内网/保留地址。"""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True  # 非法 IP 当作私有处理


class GeoIPResolver:
    """GeoIP 解析器，封装 geoip2.Reader。

    用法:
        resolver = GeoIPResolver()
        info = resolver.lookup("8.8.8.8")
        if info:
            print(info.country_code, info.city)
    """

    def __init__(
        self,
        city_db_path: str = "./data/geoip/GeoLite2-City.mmdb",
        asn_db_path: str = "./data/geoip/GeoLite2-ASN.mmdb",
        country_db_path: str = "./data/geoip/GeoLite2-Country.mmdb",
    ):
        self.city_db_path = Path(city_db_path)
        self.asn_db_path = Path(asn_db_path)
        self.country_db_path = Path(country_db_path)
        self._city_reader = None
        self._country_reader = None
        self._asn_reader = None
        self._available = False
        self._cache: dict[str, GeoInfo] = {}

        self._init_readers()

    def _init_readers(self) -> None:
        """尝试打开 GeoIP 数据库文件。

        优先级: City > Country（City 提供更详细的数据）。
        """
        city_ok = country_ok = asn_ok = False

        # 优先加载 City 数据库（含城市、经纬度）
        if self.city_db_path.exists():
            try:
                import geoip2.database
                self._city_reader = geoip2.database.Reader(str(self.city_db_path))
                city_ok = True
                logger.info("GeoIP City 数据库已加载: %s", self.city_db_path)
            except Exception as e:
                logger.warning("加载 GeoIP City 数据库失败: %s", e)
        else:
            logger.info("GeoIP City 数据库不存在: %s (跳过)", self.city_db_path)

        # 未加载 City 时尝试 Country 数据库（仅国家）
        if not city_ok and self.country_db_path.exists():
            try:
                import geoip2.database
                self._country_reader = geoip2.database.Reader(str(self.country_db_path))
                country_ok = True
                logger.info("GeoIP Country 数据库已加载: %s (作为 City 回退)", self.country_db_path)
            except Exception as e:
                logger.warning("加载 GeoIP Country 数据库失败: %s", e)
        elif not city_ok:
            logger.info("GeoIP Country 数据库不存在: %s (跳过)", self.country_db_path)

        if self.asn_db_path.exists():
            try:
                import geoip2.database
                self._asn_reader = geoip2.database.Reader(str(self.asn_db_path))
                asn_ok = True
                logger.info("GeoIP ASN 数据库已加载: %s", self.asn_db_path)
            except Exception as e:
                logger.warning("加载 GeoIP ASN 数据库失败: %s", e)
        else:
            logger.info("GeoIP ASN 数据库不存在: %s (跳过)", self.asn_db_path)

        self._available = city_ok or country_ok or asn_ok
        if not self._available:
            logger.warning("GeoIP 不可用: 未找到有效的 MaxMind 数据库文件")

    @property
    def is_available(self) -> bool:
        return self._available

    def lookup(self, ip_str: str) -> Optional[GeoInfo]:
        """查询指定 IP 的地理位置信息。

        返回 GeoInfo 如果查询成功，返回 None 如果是内网 IP 或查询失败。
        结果会被缓存以避免重复查询。
        """
        if not self._available:
            return None

        if _is_private(ip_str):
            return None

        # 检查缓存
        if ip_str in self._cache:
            return self._cache[ip_str]

        info = GeoInfo()

        try:
            if self._city_reader:
                response = self._city_reader.city(ip_str)
                info.country_code = response.country.iso_code or ""
                info.country_name = response.country.name or ""
                # 取第一个行政区划作为省/州
                if response.subdivisions and len(response.subdivisions) > 0:
                    info.region = response.subdivisions[0].name or ""
                info.city = response.city.name or ""
                if response.location:
                    info.latitude = response.location.latitude or 0.0
                    info.longitude = response.location.longitude or 0.0
        except Exception:
            pass

        # 回退: 使用 Country 数据库查国家（当 City 不可用时）
        if not info.country_code and self._country_reader:
            try:
                response = self._country_reader.country(ip_str)
                info.country_code = response.country.iso_code or ""
                info.country_name = response.country.name or ""
            except Exception:
                pass

        try:
            if self._asn_reader:
                response = self._asn_reader.asn(ip_str)
                info.asn = response.autonomous_system_number or 0
                info.as_org = response.autonomous_system_organization or ""
        except Exception:
            pass

        # 即使没有查到数据也缓存（避免重复查空）
        self._cache[ip_str] = info
        return info

    def close(self) -> None:
        """关闭数据库读取器。"""
        for reader_name in ("_city_reader", "_country_reader", "_asn_reader"):
            reader = getattr(self, reader_name, None)
            if reader:
                try:
                    reader.close()
                except Exception:
                    pass
                setattr(self, reader_name, None)
        self._available = False

    def __del__(self):
        self.close()
