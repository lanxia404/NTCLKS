#!/bin/sh

# NTCLKS 構建系統測試腳本

echo "NTCLKS 構建系統測試"
echo "================="

# 獲取項目根目錄 (使用絕對路徑)
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
PROJECT_DIR="$(readlink -f "$PROJECT_DIR")"

# 清理之前可能存在的構建產物
echo "清理之前的構建產物..."
cd "$PROJECT_DIR" && make clean

# 檢查源代碼目錄是否乾淨
echo "檢查源代碼目錄清潔度..."
if find "$PROJECT_DIR/src/kernel" -name "*.o" -o -name "*.ko" -o -name "*.mod" -o -name "*.mod.c" -o -name "*.mod.o" | grep -q .; then
    echo "✗ 源代碼目錄中存在構建產物！"
    exit 1
else
    echo "✓ 源代碼目錄乾淨"
fi

echo "執行完整構建..."
cd "$PROJECT_DIR" && make

if [ $? -eq 0 ]; then
    echo "✓ 構建成功"
else
    echo "✗ 構建失敗"
    exit 1
fi

# 檢查 build 目錄中是否有正確的構建產物
if [ -f "$PROJECT_DIR/build/ntcore.ko" ] && [ -f "$PROJECT_DIR/build/ntuserd" ] && [ -f "$PROJECT_DIR/build/ntdll_shim.o" ]; then
    echo "✓ 所有構建產物存在"
else
    echo "✗ 缺少構建產物"
    exit 1
fi

# 檢查源代碼目錄是否仍保持乾淨
echo "再次檢查源代碼目錄清潔度..."
if find "$PROJECT_DIR/src/kernel" -name "*.o" -o -name "*.ko" -o -name "*.mod" -o -name "*.mod.c" -o -name "*.mod.o" | grep -q .; then
    echo "✗ 構建後源代碼目錄中存在構建產物！"
    exit 1
else
    echo "✓ 構建後源代碼目錄仍保持乾淨"
fi

echo "構建系統測試完成！"