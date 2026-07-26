#!/bin/bash
# FluxEye 前端开发模式启动脚本
# 自动检查 Node.js 环境、安装依赖、启动 Vite 开发服务器

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
NODE_VERSION="24"
INSTALLED_NODE=""

if command -v node &>/dev/null; then
    ver=$(node --version 2>&1 | grep -oP '\d+' | head -1)
    if [ "$ver" -ge 18 ] 2>/dev/null; then
        INSTALLED_NODE=$(command -v node)
    fi
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

if [ -z "$INSTALLED_NODE" ]; then
    if ! command -v fnm &>/dev/null; then
        info "安装 fnm (Fast Node Manager)..."
        curl -o- https://fnm.vercel.app/install | bash
        export PATH="$HOME/.local/share/fnm:$PATH"
    fi
    # 加载 fnm 环境（使 fnm use 生效）
    eval "$(fnm env --shell bash)" 2>/dev/null || true
    info "通过 fnm 安装 Node.js $NODE_VERSION..."
    fnm install "$NODE_VERSION" 2>&1 | grep -v "already installed"
    fnm use "$NODE_VERSION"
fi

# 重新检测 node (fnm 安装后可能不在原 PATH)
if ! command -v node &>/dev/null; then
    export PATH="$HOME/.local/share/fnm/aliases/default/bin:$PATH"
fi

NODE=$(command -v node)
info "使用 Node.js: $(node --version 2>&1)"
info "使用 npm: $(npm --version 2>&1)"

# ── 依赖安装 ────────────────────────────────────
if [ ! -d "node_modules" ]; then
    info "正在安装前端依赖..."
    npm install
    info "前端依赖安装完成"
fi

# ── 启动 ────────────────────────────────────────
info "FluxEye 前端开发模式启动中..."
echo "    开发服务器: http://localhost:5173"
echo "    API 代理 -> http://localhost:8011"
echo ""

exec npm run dev
