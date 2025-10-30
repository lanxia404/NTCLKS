# NTCLKS 測試工具

此目錄包含用於測試 NTCLKS 項目的各種工具和腳本。

## 測試工具列表

- `build_test.sh` - 測試構建系統是否正常工作，確保構建產物只出現在 build/ 目錄中
- `module_test.sh` - 測試內核模組的載入和卸載功能
- `api_test.sh` - 測試用戶空間組件和 API shim 的基本功能
- `integration_test.sh` - 執行完整的集成測試
- `run_test.sh` - 測試套件主腳本，用於運行不同類型的測試
- `test_config.conf` - 測試配置文件
- `dummy_pe_file` - 用於測試的虛擬 PE 文件

## 使用方法

要運行所有測試：

```bash
sudo ./run_test.sh all
```

要運行特定測試：

```bash
sudo ./run_test.sh build      # 構建測試
sudo ./run_test.sh module     # 模組測試
sudo ./run_test.sh api        # API 測試
sudo ./run_test.sh integration # 集成測試
```

## 兼容性

這些測試腳本使用 POSIX shell 語法編寫，兼容各種 shell 環境，包括 bash、zsh、fish 和其他 POSIX 兼容的 shell。

## 注意事項

- 大多數測試需要 root 權限才能載入內核模組
- 在運行測試前，請確保已構建項目（`make`）
- 測試可能會載入和卸載內核模組，請在測試環境中運行