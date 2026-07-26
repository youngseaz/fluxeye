#!/bin/bash
# FluxEye 生产模式启动脚本
# 自动检查环境依赖，以多 workers 模式启动

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── 颜色 ────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }

# ── uv 包管理器 ────────────────────────────────
if ! command -v uv &>/dev/null; then
    warn "uv 未安装，正在下载安装..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
    info "uv 安装完成"
fi

# ── 虚拟环境 ────────────────────────────────────
if [ ! -d ".venv" ]; then
    info "正在创建虚拟环境..."
    uv venv
fi

# ── 依赖 ────────────────────────────────────────
if [ ! -f ".venv/installed" ]; then
    info "正在安装生产依赖..."
    uv sync --no-dev
    touch .venv/installed
    info "依赖安装完成"
fi

export FLUXEYE_CONFIG="config/config.yaml"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/usr/lib:$LD_LIBRARY_PATH"

info "FluxEye 生产模式启动中..."

exec python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info
