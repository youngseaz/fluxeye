#!/bin/bash
# FluxEye 一键生产启动脚本
# 构建前端 → 启动后端生产服务

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── 颜色 ────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

cleanup() {
    echo ""
    warn "正在关闭 FluxEye 生产服务..."
    pkill -f "uvicorn app.main" 2>/dev/null || true
    info "已关闭"
}

trap cleanup EXIT INT TERM

# ── 前端构建 ────────────────────────────────────
info "正在构建前端..."
cd "$SCRIPT_DIR/frontend"
bash run_prod.sh
info "前端构建完成"

# ── 后端启动 ────────────────────────────────────
info "正在启动后端生产服务..."
cd "$SCRIPT_DIR/backend"
bash run_prod.sh
