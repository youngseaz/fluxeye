-- ClickHouse 初始化脚本 — 创建 flows 表
-- 用法: clickhouse-client --multiquery < clickhouse_init.sql
-- 或由 ClickHouseStore.initialize() 自动执行（推荐）

CREATE DATABASE IF NOT EXISTS fluxeye;

CREATE TABLE IF NOT EXISTS fluxeye.flows (
    flow_id UInt64,
    timestamp DateTime('UTC'),
    src_mac String DEFAULT '',
    dst_mac String DEFAULT '',
    src_ip String,
    dst_ip String,
    src_port UInt16,
    dst_port UInt16,
    l4_proto LowCardinality(String),
    l7_proto String,
    bytes_sent UInt64,
    bytes_recv UInt64,
    packets_sent UInt64,
    packets_recv UInt64,
    l7_meta String DEFAULT '',
    l7_category String DEFAULT '',
    duration_ms UInt32,
    interface String DEFAULT '',
    first_seen Nullable(DateTime('UTC')),
    last_seen Nullable(DateTime('UTC')),
    dst_host String DEFAULT '',
    dst_country String DEFAULT '',
    dst_region String DEFAULT '',
    dst_city String DEFAULT '',
    dst_asn UInt32 DEFAULT 0,
    dst_as_org String DEFAULT '',
    dst_lat Float64 DEFAULT 0,
    dst_lon Float64 DEFAULT 0,
    pcap_file String DEFAULT '',
    risks String DEFAULT '[]',
    risk_score UInt16 DEFAULT 0
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, src_ip, dst_ip)
TTL timestamp + INTERVAL 7 DAY
;

-- 常用查询索引（可选）
CREATE INDEX IF NOT EXISTS idx_l7 ON fluxeye.flows(l7_proto) TYPE minmax GRANULARITY 4;
CREATE INDEX IF NOT EXISTS idx_dst_host ON fluxeye.flows(dst_host) TYPE minmax GRANULARITY 4;
