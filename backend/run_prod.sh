#!/bin/bash
# FluxEye 生产模式启动脚本
# 使用 config.yaml 配置

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ── 虚拟环境 ────────────────────────────────────
if [ ! -d ".venv" ]; then
    echo "[+] 正在创建虚拟环境..."
    python3 -m venv .venv
fi

source .venv/bin/activate

# ── 依赖 ────────────────────────────────────────
if [ ! -f ".venv/installed" ]; then
    echo "[+] 正在安装依赖..."
    pip install -r requirements.txt --quiet
    touch .venv/installed
    echo "[+] 依赖安装完成"
fi

export FLUXEYE_CONFIG="config/config.yaml"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/usr/lib:$LD_LIBRARY_PATH"

exec python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 2 \
    --log-level info
