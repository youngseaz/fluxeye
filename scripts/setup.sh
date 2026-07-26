#!/usr/bin/env bash
# ============================================================================
# FluxEye — 开发环境一键部署脚本
# 用法: ./scripts/setup.sh [--no-frontend] [--no-ndpi]
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }

INSTALL_FRONTEND=true
BUILD_NDPI=true
for arg in "$@"; do
  case "$arg" in
    --no-frontend) INSTALL_FRONTEND=false ;;
    --no-ndpi)     BUILD_NDPI=false ;;
  esac
done

echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}   FluxEye 开发环境搭建                        ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo ""

# ── 1. 系统依赖检查 ────────────────────────────────────
info "检查系统依赖..."
OS="$(uname -s)"

if [ "$OS" != "Linux" ]; then
  warn "当前系统: $OS。FluxEye 的 AF_PACKET 抓包仅支持 Linux。"
  warn "你可以在 macOS/Windows 上开发后端逻辑，但抓包需在 Linux 上运行。"
fi

# 检查必要命令
for cmd in python3 node npm; do
  if ! command -v "$cmd" &>/dev/null; then
    err "未找到 $cmd，请先安装。"
    if [ "$cmd" = "python3" ]; then
      echo "   sudo apt install python3 python3-venv python3-pip"
    elif [ "$cmd" = "node" ] || [ "$cmd" = "npm" ]; then
      echo "   sudo apt install nodejs npm"
    fi
    exit 1
  fi
done
log "系统依赖检查通过 (python3=$(python3 --version 2>&1), node=$(node --version 2>&1))"

# ── 2. 后端 Python 虚拟环境 ─────────────────────────────
info "配置后端 Python 虚拟环境..."
cd "$PROJECT_DIR/backend"

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  log "Python 虚拟环境已创建: backend/.venv"
else
  log "Python 虚拟环境已存在，跳过创建"
fi

source .venv/bin/activate
pip install --quiet --upgrade pip setuptools wheel
pip install --quiet -r requirements.txt
log "后端 Python 依赖已安装 ($(pip list --format=columns 2>/dev/null | wc -l) 个包)"

# ── 3. nDPI 桥接库编译 ──────────────────────────────────
if [ "$BUILD_NDPI" = true ]; then
  info "编译 nDPI 桥接库..."
  NDPI_DIR="$PROJECT_DIR/third/nDPI"
  LIB_DIR="$PROJECT_DIR/backend/lib"

  if [ ! -d "$NDPI_DIR" ]; then
    warn "nDPI 源码未找到，跳过编译 (third/nDPI 不存在)"
    warn "如需 DPI 识别，请运行: git clone https://github.com/ntop/nDPI.git third/nDPI"
    warn "然后重新运行此脚本，或手动编译: cd third/nDPI && ./autogen.sh && ./configure && make"
  elif [ ! -f "$NDPI_DIR/src/lib/.libs/libndpi.so" ] && [ ! -f "$NDPI_DIR/src/lib/libndpi.so" ]; then
    log "编译 nDPI..."
    cd "$NDPI_DIR"
    if [ ! -f "configure" ]; then
      ./autogen.sh
    fi
    ./configure --enable-shared --disable-example --quiet
    make -j"$(nproc)" --quiet 2>/dev/null || make -j"$(nproc)"
    cd "$PROJECT_DIR"
    log "nDPI 编译完成"
  else
    log "nDPI 已编译，跳过"
  fi

  # 确保桥接库存在
  if [ ! -f "$LIB_DIR/libndpi_helper.so" ]; then
    info "编译 nDPI 桥接库 (libndpi_helper.so)..."
    cd "$PROJECT_DIR/backend/lib"
    # 检测 nDPI 库位置
    NDPI_LIB=""
    for p in "$NDPI_DIR/src/lib/.libs/libndpi.so" "$NDPI_DIR/src/lib/libndpi.so"; do
      [ -f "$p" ] && NDPI_LIB="$p" && break
    done
    if [ -n "$NDPI_LIB" ]; then
      NDPI_INC="$NDPI_DIR/src/include"
      NDPI_LIB_DIR="$(dirname "$NDPI_LIB")"
      gcc -shared -fPIC -o libndpi_helper.so \
        ndpi_helper.c \
        -I"$NDPI_INC" \
        -L"$NDPI_LIB_DIR" \
        -lndpi -lpthread \
        -Wl,-rpath,"$NDPI_LIB_DIR"
      log "桥接库编译完成: $LIB_DIR/libndpi_helper.so"
    else
      err "未找到 libndpi.so，桥接库编译失败"
      warn "请检查 nDPI 编译是否成功: ls third/nDPI/src/lib/.libs/libndpi.so"
    fi
    cd "$PROJECT_DIR"
  else
    log "桥接库已存在，跳过编译"
  fi
else
  warn "跳过 nDPI 编译 (--no-ndpi)"
fi

# ── 4. 创建数据目录 ──────────────────────────────────────
info "创建数据目录..."
mkdir -p "$PROJECT_DIR/backend/data/geoip"
mkdir -p "$PROJECT_DIR/backend/data/captures"
mkdir -p "$PROJECT_DIR/backend/data/rrd"
mkdir -p "$PROJECT_DIR/backend/logs"
log "数据目录已创建"

# ── 5. 前端依赖 ─────────────────────────────────────────
if [ "$INSTALL_FRONTEND" = true ]; then
  if [ -d "$PROJECT_DIR/frontend" ]; then
    info "安装前端依赖..."
    cd "$PROJECT_DIR/frontend"
    if [ ! -d "node_modules" ]; then
      npm install --silent 2>&1 | tail -1
      log "前端依赖已安装"
    else
      log "前端依赖已存在，跳过安装"
    fi
  else
    warn "前端目录不存在 (frontend/)，跳过前端依赖安装"
  fi
else
  warn "跳过前端安装 (--no-frontend)"
fi

# ── 6. 权限检查 ──────────────────────────────────────────
info "检查抓包权限..."
CAP_CMD="$(command -v setcap || true)"
PYTHON_BIN="$(python3 -c 'import sys; print(sys.executable)' 2>/dev/null || echo '')"

if [ -n "$CAP_CMD" ] && [ -n "$PYTHON_BIN" ]; then
  if getcap "$PYTHON_BIN" 2>/dev/null | grep -q cap_net_raw; then
    log "抓包权限已配置: $PYTHON_BIN"
  else
    warn "建议添加原始套接字权限:"
    warn "  sudo setcap cap_net_raw,cap_net_admin=eip $PYTHON_BIN"
    warn "  或使用 root 运行: sudo python3 -m uvicorn app.main:app ..."
  fi
else
  warn "setcap 不可用，需用 root 运行抓包"
fi

# ── 7. GeoIP 数据库 ──────────────────────────────────────
info "检查 GeoIP 数据库..."
if ls "$PROJECT_DIR/backend/data/geoip"/*.mmdb 2>/dev/null | head -1 >/dev/null; then
  log "GeoIP 数据库已存在"
else
  warn "未找到 GeoIP 数据库，自动下载..."
  cd "$PROJECT_DIR/backend"
  source .venv/bin/activate 2>/dev/null || true
  python scripts/download_geoip.py 2>&1 || true
  if ls data/geoip/*.mmdb 2>/dev/null | head -1 >/dev/null; then
    log "GeoIP 数据库下载完成"
  else
    warn "GeoIP 数据库下载失败，可手动放置 .mmdb 文件到 backend/data/geoip/"
  fi
fi

# ── 完成 ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   FluxEye 开发环境搭建完成!                    ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo "启动方式:"
echo ""
echo "  # 1. 启动后端 (终端 1)"
echo "  cd backend && source .venv/bin/activate"
echo "  LD_LIBRARY_PATH=/usr/lib PYTHONPATH=. \\"
echo "    python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo ""
echo "  # 2. 启动前端 (终端 2)"
echo "  cd frontend && npm run dev"
echo ""
echo "  # 3. 打开浏览器 → http://localhost:5173"
echo ""
echo "  # (可选) 初始化模拟数据"
echo "  cd backend && source .venv/bin/activate && python scripts/init_db.py"
echo ""
