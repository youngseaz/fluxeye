#!/bin/bash
# FluxEye 生产模式启动脚本
# 自动检查环境依赖、编译 nDPI、以多 workers 模式启动

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
    info "安装 uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# C 编译工具链（编译 nDPI 需要）
BUILD_DEPS=(gcc make autoconf automake pkg-config)
APT_PKGS=()
for dep in "${BUILD_DEPS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        APT_PKGS+=("$dep")
    fi
done
if ! command -v libtoolize &>/dev/null; then
    APT_PKGS+=("libtool-bin")
fi
if [ ${#APT_PKGS[@]} -gt 0 ]; then
    info "安装构建工具: ${APT_PKGS[*]}"
    sudo apt install -y "${APT_PKGS[@]}"
fi

# rrdtool 开发库
if ! dpkg -s librrd-dev &>/dev/null 2>&1; then
    info "安装 librrd-dev..."
    sudo apt install -y librrd-dev
fi

# ── 虚拟环境 ────────────────────────────────────
if [ ! -d ".venv" ]; then
    info "创建虚拟环境..."
    uv venv
fi

# ── Python 依赖 ────────────────────────────────
if [ ! -f ".venv/installed" ]; then
    info "安装生产依赖..."
    uv sync --no-dev
    touch .venv/installed
fi

# ── nDPI 引擎 ──────────────────────────────────
NDPI_DIR="$SCRIPT_DIR/../third/nDPI"
NDPI_LIB="$NDPI_DIR/src/lib/libndpi.so"
BRIDGE_LIB="$SCRIPT_DIR/lib/libndpi_helper.so"

# 初始化 git 子模块（首次拉取 nDPI 源码）
if [ ! -d "$NDPI_DIR/.git" ]; then
    info "拉取 nDPI 子模块..."
    cd "$SCRIPT_DIR/.."
    git submodule update --init third/nDPI
    cd "$SCRIPT_DIR"
    info "nDPI 子模块拉取完成"
fi

# checkout 到指定 release 版本
NDPI_TAG="5.0"
CURRENT_TAG=$(cd "$NDPI_DIR" && git describe --tags --exact-match 2>/dev/null || true)
if [ "$CURRENT_TAG" != "$NDPI_TAG" ]; then
    info "切换到 nDPI $NDPI_TAG..."
    cd "$NDPI_DIR"
    git checkout "$NDPI_TAG" 2>/dev/null
    cd "$SCRIPT_DIR"
    info "nDPI 已切换到 $NDPI_TAG"
fi

if [ ! -f "$NDPI_LIB" ]; then
    info "编译 nDPI 引擎..."
    cd "$NDPI_DIR"
    ./autogen.sh --quiet 2>/dev/null
    ./configure --enable-shared --disable-example --quiet 2>/dev/null
    make -j$(nproc) 2>/dev/null
    cd "$SCRIPT_DIR"
fi

# ── nDPI 桥接库 ────────────────────────────────
if [ ! -f "$BRIDGE_LIB" ]; then
    info "编译 nDPI 桥接库..."
    cd "$SCRIPT_DIR/lib"
    gcc -shared -fPIC -o libndpi_helper.so ndpi_helper.c \
        -I"$NDPI_DIR/src/include" -I"$NDPI_DIR/src/lib" \
        -L"$NDPI_DIR/src/lib" \
        -lndpi -lpthread -lm \
        -Wl,-rpath,"$NDPI_DIR/src/lib"
    cd "$SCRIPT_DIR"
fi

# ── Python 检测 ─────────────────────────────────
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+')
        major=${ver%.*}; minor=${ver#*.}
        if [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 8 ]; }; then
            PYTHON=$(command -v "$cmd")
            break
        fi
    fi
done
if [ -z "$PYTHON" ]; then
    err "未找到 Python 3.8+，请先安装 Python"
    exit 1
fi
info "使用 Python: $($PYTHON --version 2>&1)"

# ── 激活虚拟环境 ────────────────────────────────
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
    info "已激活虚拟环境: .venv"
fi

# ── 环境变量 ────────────────────────────────────
export FLUXEYE_CONFIG="config/config.yaml"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="$NDPI_DIR/src/lib:/usr/lib:$LD_LIBRARY_PATH"

# ── 抓包权限 ────────────────────────────────────
PYTHON_BIN=$(command -v python)
if ! getcap "$PYTHON_BIN" 2>/dev/null | grep -q cap_net_raw; then
    if command -v setcap &>/dev/null; then
        info "设置 CAP_NET_RAW + CAP_NET_ADMIN 权限（需要 sudo）..."
        sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN" 2>/dev/null || \
            warn "设置权限失败，抓包可能需要 root 权限"
    fi
fi

info "FluxEye 生产模式启动中..."

exec python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info
