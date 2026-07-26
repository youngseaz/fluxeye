#!/bin/bash
# FluxEye 测试运行脚本
# 运行所有后端测试

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── 颜色 ────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[x]${NC} $1"; }

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

# ── 激活虚拟环境 ────────────────────────────────
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# ── nDPI 库路径 ─────────────────────────────────
NDPI_DIR="$SCRIPT_DIR/../third/nDPI"
if [ -f "$NDPI_DIR/src/lib/libndpi.so" ]; then
    export LD_LIBRARY_PATH="$NDPI_DIR/src/lib:$LD_LIBRARY_PATH"
fi

export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"

# ── 运行测试 ────────────────────────────────────
info "运行后端测试..."
echo ""

exec python -m pytest tests/ -v --tb=short "$@"
