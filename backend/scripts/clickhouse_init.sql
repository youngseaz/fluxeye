-- ClickHouse 初始化脚本（Docker 首次启动时自动执行）
CREATE DATABASE IF NOT EXISTS fluxeye;

CREATE TABLE IF NOT EXISTS fluxeye.flow_stats (
    timestamp     DateTime64(3)  NOT NULL,
    src_ip        IPv4           NOT NULL,
    dst_ip        IPv4           NOT NULL,
    src_port      UInt16         NOT NULL,
    dst_port      UInt16         NOT NULL,
    l4_proto      LowCardinality(String),
    l7_proto      LowCardinality(String),
    bytes_sent    UInt64         DEFAULT 0,
    bytes_recv    UInt64         DEFAULT 0,
    packets_sent  UInt64         DEFAULT 0,
    packets_recv  UInt64         DEFAULT 0,
    l7_meta       String         DEFAULT '',
    duration_ms   UInt32         DEFAULT 0
) ENGINE = MergeTree()
  PARTITION BY toYYYYMMDD(timestamp)
  ORDER BY (timestamp, l7_proto, src_ip)
  TTL timestamp + INTERVAL 90 DAY DELETE;

-- 分钟级协议聚合物化视图
CREATE MATERIALIZED VIEW IF NOT EXISTS fluxeye.proto_stats_mv
  ENGINE = SummingMergeTree()
  ORDER BY (time_bucket, l7_proto)
AS SELECT
    toStartOfMinute(timestamp) AS time_bucket,
    l7_proto,
    sum(bytes_sent + bytes_recv) AS bytes_total,
    count() AS flow_count
  FROM fluxeye.flow_stats
  GROUP BY time_bucket, l7_proto;
