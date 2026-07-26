#!/bin/bash
# FluxEye 一键开发启动脚本
# 同时启动后端 + 前端

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── 颜色 ────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

cleanup() {
    echo ""
    warn "正在关闭所有 FluxEye 进程..."
    pkill -f "uvicorn app.main" 2>/dev/null || true
    pkill -f "vite" 2>/dev/null || true
    info "已关闭"
}

trap cleanup EXIT INT TERM

# ── 后端 ────────────────────────────────────────
info "正在启动后端..."
cd "$SCRIPT_DIR/backend"
bash run_dev.sh &
BACKEND_PID=$!

# ── 前端 ────────────────────────────────────────
info "正在启动前端..."
cd "$SCRIPT_DIR/frontend"
bash run_dev.sh &
FRONTEND_PID=$!

# ── 等待 ────────────────────────────────────────
echo ""
info "FluxEye 开发环境已启动"
echo "    后端: http://localhost:8011"
echo "    前端: http://localhost:5173"
echo "    按 Ctrl+C 停止所有服务"
echo ""

wait $BACKEND_PID $FRONTEND_PID
