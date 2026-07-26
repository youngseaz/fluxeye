#!/bin/bash
#──────────────────────────────────────────────────────────────
# 交叉编译 nDPI 用于 ARM 嵌入式设备
# 在 x86_64 开发机上运行，生成 ARM 版本的 libndpi.so
#──────────────────────────────────────────────────────────────
set -euo pipefail

NDPI_SRC="${1:-../third/nDPI}"
OUTPUT_DIR="${2:-./lib}"

if [ ! -d "$NDPI_SRC" ]; then
    echo "❌ nDPI 源码目录不存在: $NDPI_SRC"
    echo "用法: $0 [nDPI源码路径] [输出目录]"
    echo "示例: $0 ../third/nDPI ./lib"
    exit 1
fi

# 检测可用的 ARM 交叉编译工具链
CROSS_COMPILE=""
for cc in aarch64-linux-gnu-gcc arm-linux-gnueabihf-gcc; do
    if command -v "$cc" &>/dev/null; then
        CROSS_COMPILE="${cc%-gcc}"
        echo "✅ 找到交叉编译工具: $CROSS_COMPILE"
        break
    fi
done

if [ -z "$CROSS_COMPILE" ]; then
    echo "⚠️  未检测到交叉编译工具链"
    echo "   请安装: sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu"
    echo ""
    echo "   或直接在 ARM 设备上原生编译："
    echo "   git clone https://github.com/ntop/nDPI.git"
    echo "   cd nDPI && ./autogen.sh && ./configure && make && sudo make install"
    exit 1
fi

cd "$NDPI_SRC"

# 清理
make clean 2>/dev/null || true

# 配置交叉编译
if [[ "$CROSS_COMPILE" == *aarch64* ]]; then
    ./configure --host=aarch64-linux-gnu --enable-shared --disable-example
else
    ./configure --host=arm-linux-gnueabihf --enable-shared --disable-example
fi

# 编译
make -j$(nproc)

# 复制产物
mkdir -p "$OUTPUT_DIR"
cp src/lib/.libs/libndpi.so* "$OUTPUT_DIR/"
cp src/lib/libndpi.so* "$OUTPUT_DIR/" 2>/dev/null || true

echo ""
echo "✅ ARM nDPI 编译完成!"
echo "   库文件: $OUTPUT_DIR/libndpi.so*"
echo ""
echo "   部署到嵌入式设备:"
echo "   scp $OUTPUT_DIR/libndpi.so* root@device:/usr/local/lib/"
echo "   ssh root@device ldconfig"
echo ""
echo "   然后在 FluxEye 的 config.yaml 中设置:"
echo "   collector:"
echo "     dpi_lib_path: /usr/local/lib/libndpi.so"
