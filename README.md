# FluxEye — DPI 可视化系统

[![License](https://img.shields.io/badge/License-LGPLv3-blue.svg)](LICENSE)

**FluxEye** 是一款面向嵌入式和服务器环境的 DPI（深度包检测）可视化系统。基于 nDPI 引擎实时解析网络流量，通过 Vue3 仪表盘呈现应用层协议分布、流量趋势、设备画像、安全态势感知等功能。

---

## 功能特性

### 📊 实时监控
- **实时仪表盘** — 流量速率(bps/pps)、活跃连接数、Top N 协议/会话
- **实时会话** — 查看当前活跃的流记录，支持 BPF 过滤录制 PCAP
- **时序图表** — 历史流量趋势折线图

### 🔍 深度包检测
- **nDPI 引擎** — 精确识别 300+ 应用层协议（YouTube、Netflix、微信、抖音等）
- **端口回退** — nDPI 不可用时自动降级为端口猜测模式
- **IPv4/IPv6 双栈** — 完整支持 IPv6 数据包解析与协议检测
- **TLS SNI 提取** — 从 TLS ClientHello 中提取服务器名称
- **DNS 解析** — 从 DNS 查询中提取域名

### 🏷️ 智能服务映射
- **618 条域名规则** — 覆盖 414 个应用服务（Google、微信、淘宝、抖音等）
- **银行/家电/IoT 识别** — 工商银行、招商银行、美的、海尔等品牌识别
- **AI 平台识别** — OpenAI/ChatGPT、DeepSeek、GitHub Copilot 等

### 🔒 安全态势感知
- **风险检测** — 基于 nDPI 风险的威胁评分（非标准端口 TLS、自签名证书等）
- **安全概览** — 按严重级别统计风险事件（严重/高危/中危/低危）
- **风险时间线** — 按时间排序的安全事件列表

### 📱 设备流量画像
- **MAC 跟踪** — 基于 MAC 地址聚合设备流量（IP 变化不影响设备识别）
- **IEEE OUI 厂商识别** — 39,702 条厂商前缀，自动识别设备品牌（华为、Cisco、Apple 等）
- **应用访问分析** — 每台设备访问过的应用服务标签
- **通信对端** — 设备与哪些 IP 通信、访问了哪些域名

### 🗂️ 存储与导出
- **SQLite（默认）** — 零配置，开箱即用
- **InfluxDB / ClickHouse** — 高性能时序存储（可选）
- **PCAP 录制** — 实时录制为 Wireshark 兼容格式，支持分段轮转
- **GeoIP** — 国家/城市/ASN 地理定位
- **WebSocket 实时推送** — 仪表盘数据自动更新

---

## 架构概览

```
网卡 (AF_PACKET) → PacketCapture (IPv4/IPv6) → nDPI DPI
                                                   ↓
           ┌─ 实时仪表盘 (WebSocket推送)          │
           │                                     ↓
  Web UI (Vue3) ← FastAPI ← Storage (SQLite) ← FlowManager
           │                                     │
           └─ PCAP 录制 ─────────────────── PcapWriter
```

---

## 快速开始 (一键脚本)

```bash
# 1. 克隆并初始化
git clone https://github.com/your/fluxeye.git
cd fluxeye
chmod +x scripts/setup.sh
./scripts/setup.sh

# 2. 启动后端 (终端 1)
cd backend
source .venv/bin/activate
LD_LIBRARY_PATH=/usr/lib PYTHONPATH=. \
  python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# 3. 启动前端 (终端 2)
cd frontend
npm run dev

# 4. 打开浏览器
#    http://localhost:5173  → FluxEye 仪表盘
#    http://localhost:8000/docs  → Swagger API 文档
```

> **抓包权限**: 首次运行时需要为 Python 添加 raw socket 权限：
> ```bash
> sudo setcap cap_net_raw,cap_net_admin=eip /path/to/your/python3
> ```
> 或者直接用 root 运行。

---

## 目录结构

```
fluxeye/
├── scripts/
│   ├── setup.sh          # 开发环境一键部署脚本
│   ├── build.sh          # 生产构建脚本 (Docker 镜像)
│   └── init_db.py        # 数据库初始化 + 模拟数据
├── backend/
│   ├── app/              # FastAPI 应用代码
│   │   ├── main.py       # 入口
│   │   ├── config.py     # 配置管理
│   │   ├── api/          # REST API 路由
│   │   ├── collector/    # 抓包 + DPI + pcap 写入
│   │   ├── flow/         # 流管理
│   │   ├── models/       # Pydantic 模型
│   │   ├── storage/      # 存储后端 (SQLite/InfluxDB/ClickHouse)
│   │   └── utils/        # 日志等工具
│   ├── lib/              # nDPI C 桥接库
│   │   ├── ndpi_helper.c
│   │   └── libndpi_helper.so  (编译产物)
│   ├── config/           # 配置文件
│   ├── data/             # 数据目录 (GeoIP DB, pcap, SQLite)
│   ├── scripts/          # 工具脚本
│   ├── Dockerfile
│   ├── pyproject.toml
│   └── pyproject.toml       # 依赖管理 (uv sync)
├── frontend/
│   ├── src/              # Vue3 组件
│   │   ├── views/        # 页面
│   │   ├── components/   # 可复用组件
│   │   ├── stores/       # Pinia 状态
│   │   ├── services/     # API 客户端
│   │   └── router/       # 路由
│   ├── package.json
│   └── vite.config.ts
├── third/nDPI/           # nDPI 源码 (可选, git submodule)
├── docker-compose.yml
└── README.md
```

---

## 环境搭建 (手动)

### 前置要求

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | ≥ 3.11 | 后端服务 |
| Node.js | ≥ 18 | 前端构建 |
| GCC | ≥ 8 | 编译 nDPI 桥接库 |
| Linux | Kernel ≥ 4.x | AF_PACKET 原始套接字抓包 |

### 1. 后端

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
uv sync
```

### 2. nDPI 引擎 (强烈推荐)

nDPI 提供精确的应用层协议识别。不安装则自动降级为端口回退模式。

```bash
# 方式 A: 使用项目内的 third/nDPI
cd third/nDPI
./autogen.sh && ./configure --enable-shared --disable-example && make -j$(nproc)

# 编译桥接库
cd ../../backend/lib
gcc -shared -fPIC -o libndpi_helper.so ndpi_helper.c \
  -I../../third/nDPI/src/include \
  -L../../third/nDPI/src/lib/.libs \
  -lndpi -lpthread -Wl,-rpath,../../third/nDPI/src/lib/.libs

# 方式 B: 系统安装 (apt)
# sudo apt install libndpi-dev
```

### 3. 前端

```bash
cd frontend
npm install
npm run dev   # 开发模式, 热重载
```

### 4. GeoIP 数据库 (可选)

```bash
cd backend
# 在 config/config.yaml 中配置 geoip.account_id / geoip.license_key
source .venv/bin/activate
python scripts/download_geoip.py
```

支持的数据源：
- **GeoLite2-Country** — 国家代码 (国旗)
- **GeoLite2-ASN** — AS 号 + 组织
- **GeoLite2-City** — 城市 + 经纬度 (部分地区不可用)

---

## 构建部署

### 方式 A: Docker Compose (推荐)

```bash
# 仅后端 (默认 SQLite)
docker compose up -d fluxeye-api

# 完整部署 (含 InfluxDB + ClickHouse)
docker compose --profile full up -d
```

### 方式 B: 生产构建脚本

```bash
# 构建所有组件 + Docker 镜像
./scripts/build.sh

# 指定镜像标签并推送到仓库
./scripts/build.sh --tag=v1.0.0 --push
```

### 方式 C: 手动 Docker 构建

```bash
# 1. 编译 nDPI
# 2. 构建前端
cd frontend && npm run build

# 3. 构建后端镜像
cd ..
docker build -t fluxeye-api:latest -f backend/Dockerfile backend/
```

### 方式 D: 裸机部署 (无 Docker)

```bash
# 1. 编译 nDPI + 桥接库 (见上方)
# 2. 构建前端
cd frontend && npm run build

# 3. 启动后端 (生产模式)
cd backend
source .venv/bin/activate
PYTHONPATH=. LD_LIBRARY_PATH=/usr/lib \
  python -m uvicorn app.main:app \
  --host 0.0.0.0 --port 8000 \
  --workers 2 \
  --log-level info

# 4. 用 Nginx 托管前端静态资源和反向代理 API
```

#### Nginx 配置示例

```nginx
server {
    listen 80;
    server_name fluxeye.example.com;

    # 前端静态资源
    root /path/to/frontend/dist;
    index index.html;

    # SPA 路由
    location / {
        try_files $uri $uri/ /index.html;
    }

    # API 反向代理
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /health {
        proxy_pass http://127.0.0.1:8000;
    }

    # WebSocket
    location /ws/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

---

## 配置参考

### 配置文件: `backend/config/config.yaml`

```yaml
storage:
  backend: sqlite                       # sqlite | influxdb | clickhouse
  retention_days: 7                     # 流记录保留天数

collector:
  interface: eth0                       # 抓包网卡
  bpf_filter: ""                        # BPF 过滤表达式
  dpi_lib_path: libndpi_helper.so       # nDPI 桥接库路径
  flush_interval: 5.0                   # 流刷出间隔 (秒)

  pcap_output:
    enabled: false                      # 是否默认开启 PCAP 录制
    dir: ./data/captures                # PCAP 文件存储目录
    max_file_size_mb: 100               # 单个文件上限
    max_file_count: 10                  # 保留文件数

geoip:
  auto_update: true                     # 自动更新 GeoIP 数据库
  update_interval_days: 7
```

所有配置项可通过环境变量覆盖（Pydantic Settings 格式）：
```bash
export FLUXEYE_STORAGE__BACKEND=influxdb
export FLUXEYE_COLLECTOR__INTERFACE=wlan0
```

---

## API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查 |
| `/api/v1/system/status` | GET | 系统状态 |
| `/api/v1/traffic/overview` | GET | 实时流量概览 |
| `/api/v1/traffic/protocols` | GET | 协议分布 |
| `/api/v1/traffic/top-talkers` | GET | Top N IP |
| `/api/v1/traffic/time-series` | GET | 时序流量 |
| `/api/v1/traffic/live` | GET | 活跃会话列表 |
| `/api/v1/traffic/conversations` | GET | 历史流查询 (分页) |
| `/api/v1/traffic/flows/{id}` | GET | 单流详情 |
| `/api/v1/traffic/top-domains` | GET | Top N 域名统计 |
| `/api/v1/traffic/app-stats` | GET | 应用协议统计 |
| `/api/v1/traffic/services` | GET | 应用服务统计 (YouTube/微信等) |
| `/api/v1/traffic/totals` | GET | 流量汇总 (含协议/分类) |
| `/api/v1/traffic/profiles` | GET | 设备画像列表 (含 MAC/厂商/应用) |
| `/api/v1/traffic/profiles/{ip}` | GET | 设备画像详情 |
| `/api/v1/capture/status` | GET | 抓包状态 |
| `/api/v1/capture/start` | POST | 启动抓包 |
| `/api/v1/capture/stop` | POST | 停止抓包 |
| `/api/v1/capture/interfaces` | GET | 网卡列表 |
| `/api/v1/capture/recording/start` | POST | 开始 PCAP 录制 |
| `/api/v1/capture/recording/stop` | POST | 停止 PCAP 录制 |
| `/api/v1/capture/recording/status` | GET | 录制状态 |
| `/api/v1/capture/pcap-files` | GET | PCAP 文件列表 |
| `/api/v1/capture/pcap-files/{name}` | GET | 下载 PCAP 文件 |
| `/api/v1/capture/pcap-files/{name}` | DELETE | 删除 PCAP 文件 |
| `/api/v1/security/overview` | GET | 安全态势概览 |
| `/api/v1/security/events` | GET | 安全事件列表 |
| `/api/v1/geo/status` | GET | GeoIP 数据库状态 |
| `/api/v1/geo/update` | POST | 更新 GeoIP 数据库 |
| `/api/v1/export/ipfix/status` | GET | IPFIX 导出状态 |
| `/api/v1/ws/live` | WS | WebSocket 实时推送 |
| `/docs` | GET | Swagger API 文档 |

---

## 抓包权限

FluxEye 使用 Linux AF_PACKET 原始套接字抓包，需要以下权限之一：

```bash
# 方式 A: 为 Python 可执行文件添加 cap_net_raw (推荐)
sudo setcap cap_net_raw,cap_net_admin=eip $(python3 -c 'import sys; print(sys.executable)')

# 方式 B: 使用 sudo 运行
sudo python3 -m uvicorn app.main:app ...

# 方式 C: Docker 部署 (docker-compose.yml 已配置)
# 容器自动获得 NET_ADMIN + NET_RAW 权限
```

验证权限：
```bash
getcap $(python3 -c 'import sys; print(sys.executable)')
# 输出示例: /usr/bin/python3.12 = cap_net_admin,cap_net_raw+eip
```

---

## PCAP 录制与下载

在 **实时会话** 页面，支持按需录制原始数据包到 `.pcap` 文件：

1. 填写 **BPF 过滤** 表达式（可选），如 `port 80 or port 443`
2. 点击 **"开始录制"** → 实时写入 PCAP 文件
3. 在文件列表中点击 **"下载"** → 用 Wireshark 打开分析
4. 点击 **"停止录制"** → 关闭当前文件

录制不影响实时会话显示，可随时开关。

---

## 常见问题

### Q: 启动后没有流量显示？
- 检查抓包权限: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`
- 检查网卡名称是否正确: 在 Web UI 中点击"刷新网卡列表"
- 检查 nDPI 是否可用: 状态栏显示 `nDPI` 或 `回退`

### Q: nDPI 未加载？
- 确认 libndpi.so 在 LD_LIBRARY_PATH 中
- 确认桥接库已编译: `ls backend/lib/libndpi_helper.so`
- 日志中应有 `DPI 引擎: nDPI 模式` 或 `DPI 引擎: 端口回退模式`

### Q: 端口 8000 被占用？
- 启动时指定其他端口: `--port 8011`
- 同时更新 `vite.config.ts` 中的 proxy target

### Q: GeoIP 数据库下载失败？
- 此地区可能无法访问 MaxMind，可手动下载并放置到 `backend/data/geoip/`
- 仅 Country + ASN 数据库即可工作

---

## 技术栈

| 层 | 技术 | 用途 |
|----|------|------|
| 抓包 | Linux AF_PACKET | 原始套接字二层抓包 (IPv4/IPv6) |
| DPI | nDPI 5.x | 应用层协议识别 (300+ 协议) |
| MAC OUI | IEEE 公共注册表 | 设备厂商识别 (39,702 条前缀) |
| 后端 | Python 3.12, FastAPI, Uvicorn | REST API + WebSocket |
| 存储 | SQLite (默认), InfluxDB, ClickHouse | 流记录持久化 |
| 前端 | Vue 3, TypeScript, Element Plus, ECharts | Web 仪表盘 |
| UI 库 | Element Plus, ECharts | 组件 + 图表 |
| 容器 | Docker, Docker Compose | 部署编排 |

```
fluxeye/
├── backend/                    # Python + FastAPI 后端
│   ├── app/
│   │   ├── main.py            # Uvicorn 入口
│   │   ├── config.py          # Pydantic 配置
│   │   ├── api/               # REST + WebSocket
│   │   ├── collector/         # 抓包 + nDPI DPI
│   │   ├── flow/              # 流管理
│   │   ├── storage/           # 可插拔存储（SQLite/InfluxDB/ClickHouse）
│   │   └── models/            # Pydantic 数据模型
│   ├── scripts/               # 工具脚本
│   └── Dockerfile
├── frontend/                   # Vue3 + ECharts 前端（开发中）
├── third/nDPI/                 # nDPI 源码（可选）
├── docker-compose.yml
└── docs/requirement.md         # 需求文档
```

---

## 性能

| 场景 | 吞吐 |
|------|------|
| 5GB/天 嵌入式 (树莓派 4) | CPU < 1%, 余量 1000x |
| nDPI x86_64 单核 | ~1.5M pps |
| nDPI ARM A72 | ~120K pps |
| SQLite 写入 (ARM) | ~10K 条/s |

---

## License

LGPLv3 — 与 nDPI 兼容。
