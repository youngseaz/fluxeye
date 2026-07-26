# FluxEye — DPI 可视化系统需求方案

## 一、项目概述

| 项目 | 内容 |
|------|------|
| 名称 | **FluxEye** — DPI 可视化系统 |
| 目标 | 在嵌入式设备上实时捕获、深度解析网络流量，通过可视化仪表盘呈现应用层协议、流量趋势、Top N 会话等 |
| 运行环境 | 嵌入式 Linux（ARM，256MB~2GB RAM），可选配中心服务器 |
| 后端技术 | **Python + FastAPI + Uvicorn** |
| 存储引擎 | **默认 SQLite**，可选 InfluxDB / ClickHouse（配置切换） |

---

## 二、系统整体架构

### 2.1 分层架构

```
┌──────────────────────────────────────────────────────────┐
│                  前端仪表盘 (Vue3 + ECharts)               │
│  实时大屏 / 历史查询 / 流详情 / 配置管理                    │
├──────────────────────────────────────────────────────────┤
│                  API 服务层 (Uvicorn + FastAPI)             │
│  RESTful API / WebSocket 实时推送 / 认证 / 后台任务         │
├──────────────────────────────────────────────────────────┤
│                    业务逻辑层                               │
│  流聚合 / Top N 计算 / 协议归类 / 异常检测                  │
├──────────────────────────────────────────────────────────┤
│                    数据存储层 (可插拔架构)                    │
│  ┌─ 默认: SQLite (主存) + RRDtool (时序) ─┐              │
│  ├─ 可选: InfluxDB                         │              │
│  └─ 可选: ClickHouse                       │              │
│  统一 Repository 接口，配置切换，无需改业务代码              │
├──────────────────────────────────────────────────────────┤
│                    采集引擎层 (Python + nDPI + pcap)         │
│  AF_PACKET 抓包 / nDPI 协议识别 / 元数据提取               │
└──────────────────────────────────────────────────────────┘
```

### 2.2 数据流

```mermaid
flowchart LR
    subgraph 嵌入式设备 [嵌入式设备]
        A[网卡流量] --> B[采集引擎<br/>nDPI + pcap]
        B --> C[流处理模块<br/>Uvicorn workers + asyncio]
        C --> D{存储引擎<br/>(配置切换)}
        D -->|默认| E[(SQLite<br/>流记录/会话)]
        D -->|可选| F[(InfluxDB)]
        D -->|可选| G[(ClickHouse)]
        E --> H[RRDtool<br/>实时时序]
        F --> H
        G --> H
        H --> I[本地轻量 API]
        E --> I
        F --> I
        G --> I
        I --> J[前端仪表盘]
    end
    
    subgraph 中心上报 [可选 - 中心服务器]
        I -.->|MQTT / HTTP| K[中心大屏]
    end
    
    style B fill:#E67E22,color:#fff
    style C fill:#27AE60,color:#fff
    style D fill:#F39C12,color:#fff
    style E fill:#F39C12,color:#fff
    style J fill:#8E44AD,color:#fff
```

---

## 三、存储方案（可插拔架构）

### 3.1 设计原则

存储层采用 **Repository 模式** 抽象，业务逻辑不感知底层数据库：

```python
# 统一存储接口
class StorageBackend(ABC):
    @abstractmethod
    async def write_flow(self, flow: FlowRecord): ...
    @abstractmethod
    async def query_overview(self, time_range: str) -> Overview: ...
    @abstractmethod
    async def query_protocols(self, time_range: str, top: int) -> list[ProtoStat]: ...
    @abstractmethod
    async def query_time_series(self, interval: str, range: str) -> list[TimePoint]: ...
    @abstractmethod
    async def query_top_talkers(self, top: int, time_range: str) -> list[Talker]: ...
    @abstractmethod
    async def query_conversations(self, page: int, size: int, **filters) -> Page[Conversation]: ...
```

通过配置切换实现：

```yaml
# config.yaml
storage:
  backend: sqlite     # sqlite | influxdb | clickhouse
  # SQLite 配置
  sqlite:
    path: /var/lib/fluxeye/fluxeye.db
    wal: true
    journal_size_limit: 1048576
  # InfluxDB 配置
  influxdb:
    url: http://localhost:8086
    token: ${INFLUXDB_TOKEN}
    org: fluxeye
    bucket: flow_stats
  # ClickHouse 配置
  clickhouse:
    host: localhost
    port: 9000
    database: fluxeye
    user: default
    password: ${CLICKHOUSE_PASSWORD}
```

### 3.2 存储选型对比

| 数据库 | 内存占用 | 写入性能 | 查询性能 | 嵌入式适用性 | 场景 |
|--------|---------|---------|---------|-------------|------|
| **SQLite** ⭐默认 | ~2MB | ~10K 条/s (ARM) | 百万级毫秒 | ✅✅✅ | 嵌入式首选，零依赖 |
| **InfluxDB** | ~512MB+ | ~100K 点/s | 时序聚合极快 | ⚠️ 仅 2GB+ RAM | 中心端 / 高性能设备 |
| **ClickHouse** | ~2GB+ | ~1M 行/s | 万亿级秒级 | ❌ 不适合边缘 | 中心端大数据分析 |
| **RRDtool** | ~5MB | 环形固定写入 | 时序读取快 | ✅✅✅ | 实时 1s 粒度时序（始终启用） |

### 3.3 各数据库存储模型

#### 3.3.1 SQLite（默认）

```sql
-- 流记录表 (5-tuple 会话)
CREATE TABLE flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_s INTEGER NOT NULL,        -- 秒级时间戳
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    l4_proto TEXT NOT NULL,              -- tcp / udp
    l7_proto TEXT NOT NULL,              -- http / dns / tls / quic / ...
    bytes_sent INTEGER DEFAULT 0,
    bytes_recv INTEGER DEFAULT 0,
    packets_sent INTEGER DEFAULT 0,
    packets_recv INTEGER DEFAULT 0,
    l7_meta TEXT,                        -- HTTP URL / TLS SNI / DNS 域名等
    duration_ms INTEGER DEFAULT 0
);

-- 协议分布聚合表 (分钟级)
CREATE TABLE proto_stats (
    time_bucket INTEGER NOT NULL,        -- 分钟级时间桶
    l7_proto TEXT NOT NULL,
    bytes_total INTEGER DEFAULT 0,
    flow_count INTEGER DEFAULT 0,
    PRIMARY KEY (time_bucket, l7_proto)
);

-- Top Talkers 聚合表
CREATE TABLE top_talkers (
    time_bucket INTEGER NOT NULL,
    ip TEXT NOT NULL,
    bytes_total INTEGER DEFAULT 0,
    direction TEXT NOT NULL,             -- ingress / egress
    PRIMARY KEY (time_bucket, ip, direction)
);

-- 索引
CREATE INDEX idx_flows_ts ON flows(timestamp_s);
CREATE INDEX idx_flows_l7 ON flows(l7_proto);
CREATE INDEX idx_flows_src ON flows(src_ip);
CREATE INDEX idx_flows_dst ON flows(dst_ip);
CREATE INDEX idx_proto_stats_bucket ON proto_stats(time_bucket);
```

#### 3.3.2 InfluxDB（可选）

使用 InfluxDB 2.x Bucket + Measurement 模型，无需预定义 Schema：

```yaml
# Measurement: flow_stats (写入点)
measurement: "flow_stats"
tags:
  - src_ip
  - dst_ip
  - src_port
  - dst_port
  - l4_proto          # tcp, udp
  - l7_proto          # http, dns, tls, quic, ...
  - direction         # ingress, egress
fields:
  - bytes_sent        # (int)
  - bytes_recv        # (int)
  - packets_sent      # (int)
  - packets_recv      # (int)
timestamp: 毫秒精度
```

查询示例 (Flux)：

```flux
// 过去 1h 协议分布 Top 10
from(bucket: "fluxeye")
  |> range(start: -1h)
  |> filter(fn: (r) => r._measurement == "flow_stats")
  |> group(columns: ["l7_proto"])
  |> aggregateColumn(every: 1m, fn: sum, column: "_value")
  |> sort(desc: true)
  |> limit(n: 10)
```

Downsampling 自动降采样策略：

```yaml
# InfluxDB 降采样
- every: 1h
  resolution: 10s
 保留: 7d
- every: 1d
  resolution: 5m
 保留: 90d
```

#### 3.3.3 ClickHouse（可选）

```sql
CREATE TABLE flow_stats (
    timestamp     DateTime64(3)  NOT NULL,
    src_ip        IPv4           NOT NULL,
    dst_ip        IPv4           NOT NULL,
    src_port      UInt16         NOT NULL,
    dst_port      UInt16         NOT NULL,
    l4_proto      LowCardinality(String),  -- tcp / udp
    l7_proto      LowCardinality(String),  -- http / dns / tls / ...
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

-- 物化视图：分钟级协议聚合
CREATE MATERIALIZED VIEW proto_stats_mv
  ENGINE = SummingMergeTree()
  ORDER BY (time_bucket, l7_proto)
AS SELECT
    toStartOfMinute(timestamp) AS time_bucket,
    l7_proto,
    sum(bytes_sent + bytes_recv) AS bytes_total,
    count() AS flow_count
  FROM flow_stats
  GROUP BY time_bucket, l7_proto;
```

### 3.4 RRDtool 时序模型（始终启用）

```
流量时序 (1s 精度, 保留 1h)
  → 合并为 5s 精度 (保留 24h)
  → 合并为 1m 精度 (保留 7d)
  → 合并为 5m 精度 (保留 30d)

DS: bps (GAUGE, 60s, 0, U)
DS: pps (GAUGE, 60s, 0, U)
DS: flow_rate (GAUGE, 60s, 0, U)
```

---

## 四、API 接口设计

| 端点 | 说明 | 参数 |
|------|------|------|
| `GET /api/v1/traffic/overview` | 实时概览 | `?time_range=5m` |
| `GET /api/v1/traffic/protocols` | 协议分布 | `?time_range=1h&top=10` |
| `GET /api/v1/traffic/top-talkers` | 流量 Top IP | `?top=20&time_range=30m` |
| `GET /api/v1/traffic/time-series` | 时序流量 | `?interval=10s&range=1h` |
| `GET /api/v1/traffic/conversations` | 会话列表 | 分页 + 过滤 |
| `GET /api/v1/traffic/flows/{id}` | 单流详情 | |
| `WS /api/v1/ws/live` | WebSocket 实时推送 | |

FastAPI 自动生成 Swagger 文档：`GET /docs`

---

## 五、前端可视化方案

### 5.1 技术栈

| 技术 | 版本 | 用途 |
|------|------|------|
| **Vue** | 3.4+ | 渐进式 UI 框架，组合式 API (Composition API) |
| TypeScript | 5+ | 类型安全 |
| ECharts | 5+ | 图表库（协议环图、时序面积图、柱状图），`vue-echarts` 封装 |
| **Element Plus** | 2.8+ | Vue3 官方组件库，替代 Ant Design |
| Vite | 5+ | 构建工具 |
| **Pinia** | 2+ | 状态管理，替代 Redux / Zustand |
| **Vue Router** | 4+ | 路由管理 |
| WebSocket | - | 实时数据推送 |
| API 客户端 | - | `openapi-typescript` 自动生成 API 客户端类型 |

### 5.2 仪表盘布局

```
┌─────────────────────────────────────────────────────────┐
│  Header: FluxEye  |  时间范围  |  刷新  |  系统状态       │
├──────────┬──────────┬──────────┬─────────────────────────┤
│  总流量   │  包速率   │  活跃流   │  当前连接数             │
│  1.2 Gbps │ 15K pps  │  2,341   │  1,892                 │
├──────────┴──────────┴──────────┴─────────────────────────┤
│  实时流量时序图 (ECharts 面积图, WebSocket 1s 推送)       │
├──────────────────────┬──────────────────────────────────┤
│  协议分布 (环形图)     │  Top 10 目标 IP (柱状图)          │
│                      │                                  │
│  HTTP ████████ 45%   │  10.0.0.1  ████████████ 1.2GB   │
│  TLS  ██████   30%   │  10.0.0.2  ████████    800MB    │
│  DNS  ███      15%   │  10.0.0.3  ██████      600MB    │
│  QUIC ██       8%    │  ...                            │
├──────────────────────┴──────────────────────────────────┤
│  实时会话列表 (表格, 自动滚动)                            │
│  时间    |  源IP        |  目标IP    |  协议  |  流量    │
│  12:001  |  192.168.1.5 |  10.0.0.1  |  HTTP  |  2.3KB  │
│  12:001  |  192.168.1.8 |  10.0.0.2  |  TLS   |  1.1KB  │
│  ...                                                     │
└──────────────────────────────────────────────────────────┘
```

### 5.3 页面路由

| 路由 | 页面 | 说明 |
|------|------|------|
| `/` | 实时仪表盘 | 核心大屏，WebSocket 实时更新 |
| `/history` | 历史查询 | 按时间/协议/IP 过滤查询 |
| `/flows/:id` | 流详情 | 单流深度分析 |
| `/settings` | 采集配置 | 网卡绑定/过滤规则/上报配置 |

---

## 六、项目目录结构

```
fluxeye/
├── backend/
│   ├── app/
│   │   ├── main.py               # FastAPI 应用入口
│   │   ├── config.py             # 配置管理 (Pydantic Settings)
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   ├── router.py         # 路由注册
│   │   │   ├── traffic.py        # 流量数据接口
│   │   │   ├── flows.py          # 流详情接口
│   │   │   └── ws.py             # WebSocket 实时推送
│   │   ├── collector/
│   │   │   ├── __init__.py
│   │   │   ├── capture.py        # pcap 抓包封装
│   │   │   └── dpi.py            # nDPI C 库绑定 (ctypes/cffi)
│   │   ├── flow/
│   │   │   ├── __init__.py
│   │   │   ├── manager.py        # 流管理 & 5-tuple 聚合
│   │   │   └── topn.py           # Top N 计算
│   │   ├── storage/
│   │   │   ├── __init__.py
│   │   │   ├── sqlite_store.py   # SQLite 存储
│   │   │   └── rrd_store.py      # RRDtool 存储
│   │   └── models/
│   │       ├── __init__.py
│   │       └── schemas.py        # Pydantic 数据模型
│   ├── scripts/
│   │   └── init_db.py            # 数据库初始化
│   ├── config/
│   │   └── config.yaml
│   ├── requirements.txt
│   ├── pyproject.toml
│   └── Dockerfile
│
├── frontend/
│   ├── src/
│   │   ├── views/
│   │   │   ├── Dashboard.vue       # 实时仪表盘
│   │   │   ├── History.vue         # 历史查询
│   │   │   ├── FlowDetail.vue      # 流详情
│   │   │   └── Settings.vue        # 配置页
│   │   ├── components/
│   │   │   ├── TrafficChart.vue    # 流量时序图 (vue-echarts)
│   │   │   ├── ProtocolPie.vue     # 协议分布图
│   │   │   ├── TopTalkers.vue      # Top IP 排行
│   │   │   ├── LiveTable.vue       # 实时会话表
│   │   │   ├── StatCards.vue       # 顶部指标卡
│   │   │   └── AppLayout.vue       # 页面布局
│   │   ├── router/
│   │   │   └── index.ts            # Vue Router 路由配置
│   │   ├── stores/
│   │   │   ├── traffic.ts          # Pinia 流量数据 store
│   │   │   └── app.ts              # Pinia 应用状态 store
│   │   ├── composables/
│   │   │   └── useWebSocket.ts     # WebSocket 组合式函数
│   │   ├── services/
│   │   │   └── api.ts              # HTTP 请求封装 (axios)
│   │   ├── types/
│   │   │   └── index.ts            # TypeScript 类型定义
│   │   ├── App.vue                 # 根组件
│   │   └── main.ts                 # 入口文件
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── tsconfig.node.json
│   ├── vite.config.ts
│   └── env.d.ts                    # 环境类型声明
│
├── docker-compose.yml         # 中心端一键部署
├── pyproject.toml              # 根项目配置
└── README.md
```

---

## 七、技术难点与对策

| 难点 | 方案 |
|------|------|
| **nDPI 与 Python 集成** | 使用 `ctypes` / `cffi` 调用 nDPI 共享库 (.so)，封装为 Python 模块 |
| **嵌入式资源受限** | SQLite WAL 模式 + RRDtool 环形缓冲，总内存占用 < 50MB |
| **可插拔存储架构** | Repository 抽象基类 + 工厂模式，配置切换 `sqlite` / `influxdb` / `clickhouse`，业务代码零改动 |
| **高吞吐抓包** | AF_PACKET + BPF + `pypcap` / `scapy` 封装 |
| **实时推送** | FastAPI `WebSocket` + `asyncio` 后台任务，1s 窗口批量聚合推送 |
| **eMMC/SD 写入寿命** | RRDtool 固定大小文件，SQLite 适当调大 `journal_size_limit` |
| **跨平台部署** | Python 解释器 + pip 安装，无需交叉编译；ARM 上直接 `pip install` |

---

## 八、实施路线图

### Phase 1（1.5 周）— 核心链路打通
- Uvicorn + FastAPI 项目骨架：ASGI 服务器 + Pydantic 模型 + 路由注册
- 采集引擎：pcap 抓包 + nDPI 识别 → 控制台输出
- API 服务：模拟数据接口 + Swagger 文档
- 前端：静态仪表盘 + ECharts 展示模拟数据

### Phase 2（1.5 周）— 数据持久化
- 定义 `StorageBackend` 抽象基类 + 工厂模式
- SQLite 实现 (`aiosqlite`)：流记录、协议聚合写入
- InfluxDB 实现 (`influxdb-client`)：可插拔切换
- ClickHouse 实现 (`clickhouse-driver`)：可插拔切换
- RRDtool 集成 (`rrdtool` Python 绑定)：实时时序存储
- 流处理模块：5-tuple 聚合 + asyncio 后台任务
- 前端接入真实 API + WebSocket 实时推流

### Phase 3（1 周）— 完善 & 部署
- Docker Compose 中心端编排（含 InfluxDB / ClickHouse 可选服务）
- `python-dotenv` / Pydantic Settings 配置管理
- ARM 部署文档：交叉编译 nDPI `.so` + pip 安装
- 性能调优 & 文档

---

## 九、嵌入式环境最低需求

| 资源 | 最低配置 | 推荐配置 |
|------|---------|---------|
| CPU | ARM Cortex-A7 单核 @ 1GHz | ARM Cortex-A53 四核 @ 1.5GHz |
| RAM | 256MB | 512MB+ |
| 存储 | 8GB eMMC/SD | 16GB+ |
| 网卡 | 1× Gigabit Ethernet | 2× Gigabit Ethernet（镜像口+管理口）|
| Python | 3.10+ | 3.11+ |
| OS | Linux Kernel 4.19+ | Linux Kernel 5.10+ |
| 典型设备 | 树莓派 Zero 2W | 树莓派 4/5、RK3568 开发板 |

## 十、FastAPI 选型优势总结

| 对比维度 | Go + Gin (原方案) | Python + FastAPI (现方案) |
|---------|-----------------|-------------------------|
| 开发效率 | 类型安全，编译检查，开发较慢 | 动态语言 + 自动重载，**开发速度快 2-3x** |
| 异步支持 | goroutine 原生 | **Uvicorn** + `asyncio` worker，足矣 |
| 嵌入式资源 | 二进制小 (~10MB)，无依赖 | 需 Python 解释器 (~30MB)，**略重但可接受** |
| nDPI 集成 | CGo 交叉编译繁琐 | `ctypes` 加载 `.so`，**ARM 上直接 pip 或拷贝 .so** |
| API 文档 | 需手动编写 / 第三方工具 | **FastAPI 自动生成 Swagger + ReDoc** |
| 数据科学生态 | Go 库较少 | **Python 原生支持** numpy/pandas/duckdb 数据分析 |
| 多数据库支持 | 需手动实现每个后端 | Repository 抽象 + 工厂模式，**配置即切换** |
| 启动速度 | 毫秒级 | ~0.5s (FastAPI 加载) |
| 社区与维护 | 社区活跃 | 社区更活跃，DS/ML 生态更丰富 |

> **结论：** 对于嵌入式 DPI 场景，Go 的优势（极致性能、小二进制）并不关键（流量仅 5GB/天），而 FastAPI 的开发效率、自动 API 文档、Python 数据生态、多数据库灵活切换带来的收益更大。改用 FastAPI 是合理的选择。
