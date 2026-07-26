#!/bin/bash
# FluxEye 一键测试脚本
# 运行所有后端测试

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }

info "运行 FluxEye 测试..."
cd "$SCRIPT_DIR/backend"
exec bash run_test.sh "$@"
