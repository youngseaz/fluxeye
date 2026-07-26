# FluxEye — DPI Visualization System

[![License](https://img.shields.io/badge/License-LGPLv3-blue.svg)](LICENSE)

**FluxEye** is a DPI (Deep Packet Inspection) visualization system designed for embedded and server environments. It uses the nDPI engine for real-time network traffic analysis and provides a Vue3 dashboard for visualizing application-layer protocols, traffic trends, device profiles, and security threat awareness.

---

## Features

### 📊 Real-Time Monitoring
- **Live Dashboard** — Traffic rate (bps/pps), active connections, Top N protocols/sessions
- **Live Sessions** — View active flow records, BPF filtering, on-demand PCAP recording
- **Time Series Charts** — Historical traffic trend line charts

### 🔍 Deep Packet Inspection
- **nDPI Engine** — Accurate identification of 300+ application protocols (YouTube, Netflix, WeChat, Douyin, etc.)
- **Port Fallback** — Automatic degradation to port-based guessing when nDPI is unavailable
- **IPv4/IPv6 Dual Stack** — Full IPv6 packet parsing and protocol detection
- **TLS SNI Extraction** — Extract server names from TLS ClientHello
- **DNS Parsing** — Extract domain names from DNS queries

### 🏷️ Smart Service Mapping
- **618 Domain Rules** — Covering 414 application services (Google, WeChat, Taobao, Douyin, etc.)
- **Bank/Appliance/IoT Recognition** — Identify ICBC, CMB, Midea, Haier, and other brands
- **AI Platform Detection** — OpenAI/ChatGPT, DeepSeek, GitHub Copilot, etc.

### 🔒 Security Awareness
- **Risk Detection** — nDPI-based threat scoring (non-standard port TLS, self-signed certs, etc.)
- **Security Overview** — Risk events aggregated by severity (Critical/High/Medium/Low)
- **Risk Timeline** — Chronological list of security events

### 📱 Device Profiling
- **MAC Tracking** — Device traffic aggregated by MAC address (IP changes don't affect device identity)
- **IEEE OUI Vendor Identification** — 39,702 vendor prefixes for automatic device brand recognition (Huawei, Cisco, Apple, etc.)
- **Application Access Analysis** — Service tags showing which apps each device has accessed
- **Communication Peers** — Which IPs the device talks to, which domains it visits

### 🗂️ Storage & Export
- **SQLite (Default)** — Zero configuration, ready out of the box
- **InfluxDB / ClickHouse** — High-performance time-series storage (optional)
- **PCAP Recording** — Real-time capture to Wireshark-compatible format with file rotation
- **GeoIP** — Country/city/ASN geolocation
- **WebSocket Push** — Auto-updating dashboard data

---

## Architecture

```
NIC (AF_PACKET) → PacketCapture (IPv4/IPv6) → nDPI DPI
                                                   ↓
           ┌─ Live Dashboard (WebSocket push)     │
           │                                     ↓
  Web UI (Vue3) ← FastAPI ← Storage (SQLite) ← FlowManager
           │                                     │
           └─ PCAP Recording ──────────── PcapWriter
```

---

## Quick Start

### Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | ≥ 3.11 | Backend service |
| Node.js | ≥ 18 | Frontend build |
| GCC | ≥ 8 | Compile nDPI bridge library |
| Linux | Kernel ≥ 4.x | AF_PACKET raw socket capture |

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
uv sync
```

### 2. nDPI Engine (Recommended)

nDPI provides accurate application layer protocol detection. Without it, the system falls back to port-based guessing.

```bash
# Option A: Use bundled third/nDPI
cd third/nDPI
./autogen.sh && ./configure --enable-shared --disable-example && make -j$(nproc)

# Compile the bridge library
cd ../../backend/lib
gcc -shared -fPIC -o libndpi_helper.so ndpi_helper.c \
  -I../../third/nDPI/src/include \
  -L../../third/nDPI/src/lib/.libs \
  -lndpi -lpthread -Wl,-rpath,../../third/nDPI/src/lib/.libs

# Option B: System install (apt)
# sudo apt install libndpi-dev
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev   # Dev mode with hot reload
```

### 4. Start the System

```bash
# Terminal 1: Start backend (port 8000)
cd backend
source .venv/bin/activate
LD_LIBRARY_PATH=/usr/lib PYTHONPATH=. \
  python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Start frontend (port 5173)
cd frontend
npm run dev
```

Open **http://localhost:5173** for the FluxEye dashboard, or **http://localhost:8000/docs** for Swagger API docs.

> **Capture Privileges**: First-time setup requires raw socket capabilities:
> ```bash
> sudo setcap cap_net_raw,cap_net_admin=eip /path/to/your/python3
> ```

### 5. GeoIP Database (Optional)

```bash
cd backend
# Configure geoip.account_id / geoip.license_key in config/config.yaml
source .venv/bin/activate
python scripts/download_geoip.py
```

Supported data sources:
- **GeoLite2-Country** — Country code (flag)
- **GeoLite2-ASN** — AS number + organization
- **GeoLite2-City** — City + coordinates (limited availability)

---

## Directory Structure

```
fluxeye/
├── scripts/
│   ├── setup.sh          # One-click development setup
│   ├── build.sh          # Production build (Docker images)
│   └── init_db.py        # Database initialization + sample data
├── backend/
│   ├── app/              # FastAPI application
│   │   ├── main.py       # Entry point
│   │   ├── config.py     # Configuration management
│   │   ├── api/          # REST API routes
│   │   ├── collector/    # Packet capture + DPI + pcap writer
│   │   ├── flow/         # Flow management
│   │   ├── geo/          # GeoIP resolver + MAC OUI vendor lookup
│   │   ├── models/       # Pydantic models
│   │   ├── storage/      # Storage backends (SQLite/InfluxDB/ClickHouse)
│   │   └── utils/        # Logging utilities
│   ├── lib/              # nDPI C bridge library
│   │   ├── ndpi_helper.c
│   │   └── libndpi_helper.so  (compiled)
│   ├── config/           # Configuration files
│   ├── data/             # Data directory (GeoIP DB, pcap, SQLite, OUI cache)
│   ├── scripts/          # Utility scripts
│   ├── tests/            # Test suite (169+ tests)
│   ├── Dockerfile
│   ├── pyproject.toml
│   └── pyproject.toml       # Dependency management (uv sync)
├── frontend/
│   ├── src/              # Vue3 components
│   │   ├── views/        # Pages
│   │   ├── components/   # Reusable components
│   │   ├── stores/       # Pinia state management
│   │   ├── services/     # API client
│   │   └── router/       # Routes
│   ├── package.json
│   └── vite.config.ts
├── third/nDPI/           # nDPI source (optional, git submodule)
├── docker-compose.yml
├── README.md
└── README.en.md
```

---

## Deployment

### Option A: Docker Compose

```bash
# Backend only (default SQLite)
docker compose up -d fluxeye-api

# Full stack (with InfluxDB + ClickHouse)
docker compose --profile full up -d
```

### Option B: Production Build

```bash
# Build all components + Docker image
./scripts/build.sh

# Specify image tag and push
./scripts/build.sh --tag=v1.0.0 --push
```

### Option C: Manual Docker Build

```bash
# 1. Compile nDPI
# 2. Build frontend
cd frontend && npm run build

# 3. Build backend image
cd ..
docker build -t fluxeye-api:latest -f backend/Dockerfile backend/
```

---

## Configuration

### Config file: `backend/config/config.yaml`

```yaml
storage:
  backend: sqlite                       # sqlite | influxdb | clickhouse
  retention_days: 7                     # Flow record retention days

collector:
  interface: eth0                       # Capture interface
  bpf_filter: ""                        # BPF filter expression
  dpi_lib_path: libndpi_helper.so       # nDPI bridge library path
  flush_interval: 5.0                   # Flow flush interval (seconds)

  pcap_output:
    enabled: false                      # Enable PCAP recording by default
    dir: ./data/captures                # PCAP file directory
    max_file_size_mb: 100               # Max file size
    max_file_count: 10                  # File retention count

geoip:
  auto_update: true                     # Auto-update GeoIP database
  update_interval_days: 7
```

All settings can be overridden via environment variables (Pydantic Settings format):
```bash
export FLUXEYE_STORAGE__BACKEND=influxdb
export FLUXEYE_COLLECTOR__INTERFACE=wlan0
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/system/status` | GET | System status |
| `/api/v1/traffic/overview` | GET | Real-time traffic overview |
| `/api/v1/traffic/protocols` | GET | Protocol distribution |
| `/api/v1/traffic/top-talkers` | GET | Top N IPs |
| `/api/v1/traffic/time-series` | GET | Time series traffic |
| `/api/v1/traffic/live` | GET | Active session list |
| `/api/v1/traffic/conversations` | GET | Historical flow query (paged) |
| `/api/v1/traffic/flows/{id}` | GET | Single flow detail |
| `/api/v1/traffic/top-domains` | GET | Top N domain stats |
| `/api/v1/traffic/app-stats` | GET | Application protocol stats |
| `/api/v1/traffic/services` | GET | Service stats (YouTube/WeChat etc.) |
| `/api/v1/traffic/totals` | GET | Traffic totals (by protocol/category) |
| `/api/v1/traffic/profiles` | GET | Device profiles (MAC/vendor/apps) |
| `/api/v1/traffic/profiles/{ip}` | GET | Device profile detail |
| `/api/v1/capture/status` | GET | Capture status |
| `/api/v1/capture/start` | POST | Start capture |
| `/api/v1/capture/stop` | POST | Stop capture |
| `/api/v1/capture/interfaces` | GET | Network interface list |
| `/api/v1/capture/recording/start` | POST | Start PCAP recording |
| `/api/v1/capture/recording/stop` | POST | Stop PCAP recording |
| `/api/v1/capture/recording/status` | GET | Recording status |
| `/api/v1/capture/pcap-files` | GET | PCAP file list |
| `/api/v1/capture/pcap-files/{name}` | GET | Download PCAP file |
| `/api/v1/capture/pcap-files/{name}` | DELETE | Delete PCAP file |
| `/api/v1/security/overview` | GET | Security overview |
| `/api/v1/security/events` | GET | Security events list |
| `/api/v1/geo/status` | GET | GeoIP database status |
| `/api/v1/geo/update` | POST | Update GeoIP database |
| `/api/v1/export/ipfix/status` | GET | IPFIX export status |
| `/api/v1/ws/live` | WS | WebSocket real-time push |
| `/docs` | GET | Swagger API documentation |

---

## PCAP Recording

On the **Live Sessions** page, you can record raw packets to `.pcap` files on demand:

1. Enter a **BPF filter** expression (optional), e.g. `port 80 or port 443`
2. Click **"Start Recording"** → writes packets to a PCAP file in real-time
3. Click **"Download"** in the file list → open with Wireshark
4. Click **"Stop Recording"** → close the current file

Recording does not affect live session display and can be toggled at any time.

---

## Capture Privileges

FluxEye uses Linux AF_PACKET raw sockets for packet capture. One of the following is required:

```bash
# Method A: Add cap_net_raw to Python (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip $(python3 -c 'import sys; print(sys.executable)')

# Method B: Run with sudo
sudo python3 -m uvicorn app.main:app ...

# Method C: Docker deployment (docker-compose.yml configured)
# Container automatically gets NET_ADMIN + NET_RAW capabilities
```

Verify privileges:
```bash
getcap $(python3 -c 'import sys; print(sys.executable)')
# Example output: /usr/bin/python3.12 = cap_net_admin,cap_net_raw+eip
```

---

## OUI MAC Vendor Database

FluxEye downloads the IEEE OUI registry to identify device manufacturers by MAC address:

- **Source**: [IEEE Public Listing](https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries)
- **Coverage**: 39,702 vendor prefixes (MA-L / OUI-24)
- **Auto-update**: Via API (`POST /api/v1/geo/update`) or manual download
- **Cache**: Stored in `data/oui_vendors.json`

Supported formats: Cisco, Huawei, Apple, Samsung, Xiaomi, TP-Link, and thousands more.

---

## FAQ

### Q: No traffic displayed after startup?
- Check capture privileges: `sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)`
- Verify the network interface name in Web UI
- Check if nDPI is loaded: status bar shows `nDPI` or `Fallback`

### Q: nDPI not loading?
- Ensure libndpi.so is in `LD_LIBRARY_PATH`
- Verify bridge library exists: `ls backend/lib/libndpi_helper.so`
- Logs should show `DPI 引擎: nDPI 模式` or `DPI 引擎: 端口回退模式`

### Q: Port 8000 already in use?
- Specify another port: `--port 8011`
- Update `vite.config.ts` proxy target accordingly

### Q: GeoIP database download fails?
- Manual download and place in `backend/data/geoip/`
- Country + ASN databases are sufficient for basic functionality

### Q: Tests fail?
```bash
cd backend
PYTHONPATH=. LD_LIBRARY_PATH=/usr/lib .venv/bin/python -m pytest tests/ -v
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Capture | Linux AF_PACKET | L2 raw socket capture (IPv4/IPv6) |
| DPI | nDPI 5.x | Application protocol detection (300+ protocols) |
| MAC OUI | IEEE Public Registry | Device vendor identification (39,702 prefixes) |
| Backend | Python 3.12, FastAPI, Uvicorn | REST API + WebSocket |
| Storage | SQLite (default), InfluxDB, ClickHouse | Flow record persistence |
| Frontend | Vue 3, TypeScript, Element Plus, ECharts | Web dashboard |

---

## Test Coverage

The project includes **169+ tests** covering:

- **32 API integration tests** — All REST endpoints + WebSocket
- **53 packet parsing tests** — IPv4/IPv6, Ethernet, TCP/UDP, DNS, TLS SNI
- **21 service mapping tests** — Domain → service name mapping logic
- **37 SQLite storage tests** — CRUD, queries, security, device profiles
- **17 MAC OUI vendor tests** — Lookup, normalization, vendor aliases
- **9 flow manager tests** — Flow key, aggregation, timeout, metadata

---

## License

This project is licensed under the **LGPLv3** license. See the [LICENSE](LICENSE) file for details.
