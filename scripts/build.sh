#!/usr/bin/env bash
# ============================================================================
# FluxEye — 生产构建脚本
# 构建前端静态资源、后端 Docker 镜像
# 用法: ./scripts/build.sh [--tag latest] [--push]
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }

TAG="latest"
PUSH=false
for arg in "$@"; do
  case "$arg" in
    --tag=*)    TAG="${arg#*=}" ;;
    --push)     PUSH=true ;;
  esac
done

echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo -e "${CYAN}   FluxEye 生产构建                              ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
echo ""

# ── 1. 编译 nDPI ────────────────────────────────────────
info "编译 nDPI..."
NDPI_DIR="$PROJECT_DIR/third/nDPI"
LIB_DIR="$PROJECT_DIR/backend/lib"

if [ -d "$NDPI_DIR" ]; then
  cd "$NDPI_DIR"
  if [ ! -f "configure" ]; then
    ./autogen.sh --quiet
  fi
  ./configure --enable-shared --disable-example --quiet
  make -j"$(nproc)" --quiet 2>/dev/null || make -j"$(nproc)"
  cd "$PROJECT_DIR"
  log "nDPI 编译完成"

  # 编译桥接库
  NDPI_LIB=""
  for p in "$NDPI_DIR/src/lib/.libs/libndpi.so" "$NDPI_DIR/src/lib/libndpi.so"; do
    [ -f "$p" ] && NDPI_LIB="$p" && break
  done
  if [ -n "$NDPI_LIB" ]; then
    gcc -shared -fPIC -o "$LIB_DIR/libndpi_helper.so" \
      "$LIB_DIR/ndpi_helper.c" \
      -I"$NDPI_DIR/src/include" \
      -L"$(dirname "$NDPI_LIB")" \
      -lndpi -lpthread \
      -Wl,-rpath,'$ORIGIN'
    log "桥接库编译完成: $LIB_DIR/libndpi_helper.so"
  fi
else
  warn "nDPI 源码不存在 ($NDPI_DIR)，跳过 nDPI 编译"
  warn "如需 DPI 功能，请先: git clone https://github.com/ntop/nDPI.git third/nDPI"
fi

# ── 2. 构建前端 ──────────────────────────────────────────
info "构建前端静态资源..."
if [ -d "$PROJECT_DIR/frontend" ]; then
  cd "$PROJECT_DIR/frontend"
  if [ ! -d "node_modules" ]; then
    npm install --silent
  fi
  npm run build 2>&1
  log "前端构建完成: frontend/dist/"
else
  warn "前端目录不存在，跳过前端构建"
fi

# ── 3. 构建 Docker 镜像 ──────────────────────────────────
info "构建 Docker 镜像..."

# 后端镜像
BACKEND_IMAGE="fluxeye-api:${TAG}"
cd "$PROJECT_DIR"
docker build -t "$BACKEND_IMAGE" -f backend/Dockerfile backend/
log "后端镜像已构建: $BACKEND_IMAGE"

# 全栈镜像 (后端 + 前端静态资源)
FULLSTACK_IMAGE="fluxeye:${TAG}"
if [ -d "$PROJECT_DIR/frontend/dist" ]; then
  cat > /tmp/fluxeye.Dockerfile << 'DOCKERFILE'
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev libndpi-dev && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ .
COPY frontend/dist /app/static
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
DOCKERFILE

  # 静态文件服务配置 — 让 FastAPI 挂载 static 目录
  docker build -t "$FULLSTACK_IMAGE" -f /tmp/fluxeye.Dockerfile .
  log "全栈镜像已构建: $FULLSTACK_IMAGE"
fi

# ── 4. (可选) 推送镜像 ──────────────────────────────────
if [ "$PUSH" = true ]; then
  info "推送镜像到仓库..."
  docker push "$BACKEND_IMAGE"
  if [ -n "${FULLSTACK_IMAGE:-}" ]; then
    docker push "$FULLSTACK_IMAGE"
  fi
  log "镜像已推送"
fi

# ── 完成 ──────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   FluxEye 构建完成!                             ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo "镜像:"
echo "  $BACKEND_IMAGE"
echo "  ${FULLSTACK_IMAGE:-}(全栈, 含前端静态资源)"
echo ""
echo "启动:"
echo "  docker compose up -d"
echo "  # 或单独启动后端:"
echo "  docker run -d --rm --name fluxeye-api \\"
echo "    --cap-add=NET_ADMIN --cap-add=NET_RAW \\"
echo "    -p 8000:8000 \\"
echo "    $BACKEND_IMAGE"
echo ""
