#!/bin/bash
# FluxEye 前端生产构建脚本
# 自动检查 Node.js 环境、安装依赖、执行生产构建

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── 颜色 ────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

# ── 系统依赖检测 ────────────────────────────────
APT_PKGS=()
if ! command -v curl &>/dev/null; then APT_PKGS+=("curl"); fi
if ! command -v unzip &>/dev/null; then APT_PKGS+=("unzip"); fi
if [ ${#APT_PKGS[@]} -gt 0 ]; then
    info "安装前端工具: ${APT_PKGS[*]}"
    sudo apt install -y "${APT_PKGS[@]}"
fi

# ── Node.js / fnm 检测 ──────────────────────────
if command -v node &>/dev/null; then
    ver=$(node --version 2>&1 | grep -oP '\d+' | head -1)
    if [ "$ver" -lt 18 ] 2>/dev/null; then
        NODE_NEEDED=1
    else
        NODE_NEEDED=0
    fi
else
    NODE_NEEDED=1
fi

# 在常见路径中查找 fnm（不一定在 PATH 中）
if ! command -v fnm &>/dev/null; then
    for fnm_path in "$HOME/.local/share/fnm/fnm" "$HOME/.fnm/fnm"; do
        if [ -x "$fnm_path" ]; then
            export PATH="$(dirname "$fnm_path"):$PATH"
            break
        fi
    done
fi

if [ "$NODE_NEEDED" -eq 1 ]; then
    if ! command -v fnm &>/dev/null; then
        info "安装 fnm (Fast Node Manager)..."
        curl -o- https://fnm.vercel.app/install | bash
        export PATH="$HOME/.local/share/fnm:$PATH"
    fi
    # 加载 fnm 环境（使 fnm use 生效）
    eval "$(fnm env --shell bash)" 2>/dev/null || true
    info "通过 fnm 安装 Node.js 24..."
    fnm install 24 2>&1 | grep -v "already installed"
    fnm use 24
fi

# 重新检测 node (fnm 安装后可能不在原 PATH)
if ! command -v node &>/dev/null; then
    export PATH="$HOME/.local/share/fnm/aliases/default/bin:$PATH"
fi

info "使用 Node.js: $(node --version 2>&1)"
info "使用 npm: $(npm --version 2>&1)"

# ── 依赖安装 ────────────────────────────────────
if [ ! -d "node_modules" ]; then
    info "正在安装前端依赖..."
    npm install
    info "前端依赖安装完成"
fi

# ── 生产构建 ────────────────────────────────────
info "正在执行生产构建..."
npm run build
info "前端构建完成"
echo "    构建产物: $SCRIPT_DIR/dist/"
