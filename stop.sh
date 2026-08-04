#!/bin/bash
# FluxEye 一键停止脚本
# 停止后端 (uvicorn) 与前端开发服务器 (vite) 进程

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── 颜色 ────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

# 停止匹配指定模式的进程（存在则停止并返回 0，否则返回 1）
stop_matching() {
    local pattern="$1" label="$2"
    if pgrep -f "$pattern" >/dev/null 2>&1; then
        local pids
        pids=$(pgrep -f "$pattern" | tr '\n' ' ')
        warn "正在停止 $label (PID: ${pids% })..."
        pkill -f "$pattern" 2>/dev/null || true
        return 0
    fi
    return 1
}

# ── 停止后端 (uvicorn) ──────────────────────────
stop_matching "uvicorn app.main" "后端服务 (uvicorn)"

# ── 停止前端开发服务器 (vite) ───────────────────
stop_matching "vite" "前端开发服务器 (vite)"

# ── 等待进程退出 ────────────────────────────────
sleep 1

# ── 状态确认 ────────────────────────────────────
if pgrep -f "uvicorn app.main" >/dev/null 2>&1 || pgrep -f "vite" >/dev/null 2>&1; then
    err "仍有 FluxEye 进程未退出，请手动检查："
    ps aux | grep -E "uvicorn app.main|vite" | grep -v grep || true
    exit 1
fi

info "所有 FluxEye 进程已停止"
exit 0
