#!/bin/sh

# NTCLKS 模組載入測試腳本

echo "NTCLKS 模組載入測試"
echo "=================="

# 獲取項目根目錄
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
PROJECT_DIR="$(readlink -f "$PROJECT_DIR")"

# 檢查是否為 root
if [ "$(id -u)" -ne 0 ]; then
    echo "請以 root 權限執行此腳本"
    exit 1
fi

# 檢查 build 目錄中是否有模組
if [ ! -f "$PROJECT_DIR/build/ntcore.ko" ]; then
    echo "錯誤: 找不到 $PROJECT_DIR/build/ntcore.ko，請先構建項目"
    exit 1
fi

echo "載入 NTCLKS 模組..."
insmod "$PROJECT_DIR/build/ntcore.ko"

if [ $? -eq 0 ]; then
    echo "✓ 模組載入成功"
else
    echo "✗ 模組載入失敗"
    exit 1
fi

# 檢查設備是否創建
if [ -e "/dev/ntcore" ]; then
    echo "✓ /dev/ntcore 設備創建成功"
else
    echo "✗ /dev/ntcore 設備未創建"
    rmmod ntcore 2>/dev/null
    exit 1
fi

echo "卸載 NTCLKS 模組..."
rmmod ntcore

if [ $? -eq 0 ]; then
    echo "✓ 模組卸載成功"
else
    echo "✗ 模組卸載失敗"
    exit 1
fi

echo "通過所有測試！"