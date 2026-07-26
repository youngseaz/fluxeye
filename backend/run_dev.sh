#!/bin/bash
# FluxEye 开发模式启动脚本
# 自动检查环境依赖、编译 nDPI 桥接库、启动热重载服务

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── 颜色 ────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

# ── 系统依赖检测 ────────────────────────────────
info "检查系统依赖..."

# uv 包管理器
if ! command -v uv &>/dev/null; then
    warn "uv 未安装，正在下载安装..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    info "uv 安装完成"
fi

# C 编译工具链
BUILD_DEPS=(gcc make autoconf automake libtool pkg-config)
MISSING=()
for dep in "${BUILD_DEPS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        MISSING+=("$dep")
    fi
done
if [ ${#MISSING[@]} -gt 0 ]; then
    err "缺少构建工具: ${MISSING[*]}"
    err "请安装: sudo apt install ${MISSING[*]}"
    exit 1
fi

# rrdtool 开发库（pip 包 rrdtool 需要 rrd.h）
if ! dpkg -s librrd-dev &>/dev/null 2>&1; then
    warn "缺少 librrd-dev，安装中..."
    sudo apt install -y librrd-dev
    info "librrd-dev 安装完成"
fi

# ── 虚拟环境 ────────────────────────────────────
if [ ! -d ".venv" ]; then
    info "正在创建虚拟环境..."
    uv venv
fi

# ── Python 依赖 ────────────────────────────────
if [ ! -f ".venv/installed" ]; then
    info "正在安装 Python 依赖..."
    uv sync
    touch .venv/installed
    info "Python 依赖安装完成"
fi

# ── 开发配置 ────────────────────────────────────
if [ ! -f "config/config.dev.yaml" ]; then
    info "正在创建 config/config.dev.yaml（从模板复制）..."
    cp config/config.yaml config/config.dev.yaml
    warn "请编辑 config/config.dev.yaml 填入实际配置（网卡、GeoIP 等）"
fi

# ── nDPI 引擎 ──────────────────────────────────
NDPI_DIR="$SCRIPT_DIR/../third/nDPI"
NDPI_LIB="$NDPI_DIR/src/lib/.libs/libndpi.so"
BRIDGE_LIB="$SCRIPT_DIR/lib/libndpi_helper.so"

if [ ! -f "$NDPI_LIB" ]; then
    info "正在编译 nDPI 引擎..."
    cd "$NDPI_DIR"
    ./autogen.sh --quiet 2>/dev/null
    ./configure --enable-shared --disable-example --quiet 2>/dev/null
    make -j$(nproc) 2>/dev/null
    cd "$SCRIPT_DIR"
    info "nDPI 引擎编译完成"
fi

# ── nDPI 桥接库 ────────────────────────────────
if [ ! -f "$BRIDGE_LIB" ]; then
    info "正在编译 nDPI 桥接库..."
    cd "$SCRIPT_DIR/lib"
    gcc -shared -fPIC -o libndpi_helper.so ndpi_helper.c \
        -I"$NDPI_DIR/src/include" -I"$NDPI_DIR/src/lib" \
        -L"$NDPI_DIR/src/lib/.libs" \
        -lndpi -lpthread -lm \
        -Wl,-rpath,"$NDPI_DIR/src/lib/.libs"
    cd "$SCRIPT_DIR"
    info "nDPI 桥接库编译完成"
fi

# ── 环境变量 ────────────────────────────────────
export FLUXEYE_CONFIG="config/config.dev.yaml"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="$NDPI_DIR/src/lib/.libs:/usr/lib:$LD_LIBRARY_PATH"

# ── 启动 ────────────────────────────────────────
APP_PORT=$(grep -A2 '^app:' config/config.dev.yaml | grep 'port' | awk '{print $2}')
APP_PORT=${APP_PORT:-8011}

info "FluxEye 开发模式启动中..."
echo "    配置文件: config/config.dev.yaml"
echo "    后端端口: $APP_PORT"
echo ""

exec python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port "$APP_PORT" \
    --reload \
    --log-level info
