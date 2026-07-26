#!/bin/bash
# FluxEye 开发模式启动脚本
# 使用 config.dev.yaml 配置，自动启用热重载

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

# ── 开发配置 ────────────────────────────────────
if [ ! -f "config/config.dev.yaml" ]; then
    echo "[+] 正在创建 config/config.dev.yaml（从模板复制）..."
    cp config/config.yaml config/config.dev.yaml
    echo "[!] 请编辑 config/config.dev.yaml 填入实际配置（网卡、GeoIP 等）"
fi

# ── nDPI 桥接库 ────────────────────────────────
if [ ! -f "lib/libndpi_helper.so" ]; then
    echo "[!] 未找到 lib/libndpi_helper.so，正在编译..."
    cd "$SCRIPT_DIR/lib"
    gcc -shared -fPIC -o libndpi_helper.so ndpi_helper.c \
        -I"$SCRIPT_DIR/../third/nDPI/src/include" \
        -L"$SCRIPT_DIR/../third/nDPI/src/lib/.libs" \
        -lndpi -lpthread -Wl,-rpath,"$SCRIPT_DIR/../third/nDPI/src/lib/.libs"
    cd "$SCRIPT_DIR"
    echo "[+] nDPI 桥接库编译完成"
fi

export FLUXEYE_CONFIG="config/config.dev.yaml"
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/usr/lib:$LD_LIBRARY_PATH"

echo "[+] FluxEye 开发模式启动中..."
echo "    配置文件: config/config.dev.yaml"
echo "    后端端口: $(grep -A2 '^app:' config/config.dev.yaml | grep 'port' | awk '{print $2}')"
echo ""

exec python -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8011 \
    --reload \
    --log-level info
