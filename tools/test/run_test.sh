#!/bin/sh

# NTCLKS 測試套件主腳本

echo "NTCLKS 測試套件"
echo "=============="

# 獲取腳本目錄
SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

echo "可用測試:"
echo "1. 構建系統測試 (build_test.sh)"
echo "2. 模組載入測試 (module_test.sh)" 
echo "3. API 測試 (api_test.sh)"
echo "4. 集成測試 (integration_test.sh)"
echo ""
echo "用法:"
echo "  ./run_test.sh build      - 執行構建測試"
echo "  ./run_test.sh module     - 執行模組測試"
echo "  ./run_test.sh api        - 執行 API 測試"
echo "  ./run_test.sh integration - 執行集成測試"
echo "  ./run_test.sh all        - 執行所有測試"

case $1 in
    "build")
        echo "執行構建系統測試..."
        sh "$SCRIPT_DIR/build_test.sh"
        ;;
    "module")
        echo "執行模組載入測試..."
        sh "$SCRIPT_DIR/module_test.sh"
        ;;
    "api")
        echo "執行 API 測試..."
        sh "$SCRIPT_DIR/api_test.sh"
        ;;
    "integration")
        echo "執行集成測試..."
        sh "$SCRIPT_DIR/integration_test.sh"
        ;;
    "all")
        echo "執行所有測試..."
        echo "構建測試:"
        sh "$SCRIPT_DIR/build_test.sh"
        echo ""
        echo "模組測試:"
        sh "$SCRIPT_DIR/module_test.sh"
        echo ""
        echo "API 測試:"
        sh "$SCRIPT_DIR/api_test.sh"
        echo ""
        echo "集成測試:"
        sh "$SCRIPT_DIR/integration_test.sh"
        ;;
    *)
        echo "請指定測試類型或 'all' 執行所有測試"
        exit 1
        ;;
esac