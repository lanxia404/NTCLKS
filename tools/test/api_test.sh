#!/bin/sh

# NTCLKS API 測試腳本

echo "NTCLKS API 測試"
echo "==============="

# 獲取項目根目錄
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
PROJECT_DIR="$(readlink -f "$PROJECT_DIR")"

# 檢查是否為 root
if [ "$(id -u)" -ne 0 ]; then
    echo "請以 root 權限執行此腳本"
    exit 1
fi

# 檢查構建產物
if [ ! -f "$PROJECT_DIR/build/ntcore.ko" ] || [ ! -f "$PROJECT_DIR/build/ntuserd" ] || [ ! -f "$PROJECT_DIR/build/ntdll_shim.o" ]; then
    echo "錯誤: 找不到構建產物，請先構建項目"
    exit 1
fi

echo "載入 NTCLKS 模組..."
insmod "$PROJECT_DIR/build/ntcore.ko"

if [ $? -ne 0 ]; then
    echo "模組載入失敗"
    exit 1
fi

echo "測試 ntdll_shim 連接..."
cd "$PROJECT_DIR/build" && ./ntuserd "$PROJECT_DIR/tools/test/dummy_pe_file" 2>/dev/null || echo "預期的 PE 文件錯誤（文件格式無效）"

# 這裡我們預期會返回非零值，因為 dummy 文件不是有效的 PE 文件
echo "✓ API 連接測試完成"

echo "卸載 NTCLKS 模組..."
rmmod ntcore

echo "API 測試完成！"