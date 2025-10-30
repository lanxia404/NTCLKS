#!/bin/sh

# NTCLKS 集成測試腳本

echo "NTCLKS 集成測試"
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

# 執行構建測試
echo "執行構建測試..."
sh "$SCRIPT_DIR/build_test.sh"

if [ $? -ne 0 ]; then
    echo "構建測試失敗"
    exit 1
else
    echo "構建測試通過"
fi

# 執行模組載入測試
echo "執行模組測試..."
sh "$SCRIPT_DIR/module_test.sh"

if [ $? -ne 0 ]; then
    echo "模組測試失敗"
    exit 1
else
    echo "模組測試通過"
fi

# 執行 API 測試
echo "執行 API 測試..."
sh "$SCRIPT_DIR/api_test.sh"

if [ $? -ne 0 ]; then
    echo "API 測試失敗"
    exit 1
else
    echo "API 測試通過"
fi

echo "所有集成測試通過！"