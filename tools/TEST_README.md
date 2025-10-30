# NTCLKS 測試工具

此目錄包含用於測試 NTCLKS 項目的各種工具和腳本，涵蓋構建、模組載入、API 功能和集成測試等多個方面。

## 測試工具列表

### 自動化測試腳本

- `run_test.sh` - 測試套件主腳本，用於運行不同類型的測試
- `build_test.sh` - 測試構建系統是否正常工作，確保構建產物只出現在 build/ 目錄中
- `module_test.sh` - 測試內核模組的載入和卸載功能
- `api_test.sh` - 測試用戶空間組件和 API shim 的基本功能
- `integration_test.sh` - 執行完整的集成測試，包含所有獨立測試
- `test_config.conf` - 測試配置文件

### 機能測試文件

- `object_test.c` - 測試物件管理系統（NtCreateObject, NtClose）
- `safe_memory_test.c` - 安全的記憶體管理測試（NtAllocateVirtualMemory, NtFreeVirtualMemory）
- `comprehensive_memory_test.c` - 全面的記憶體管理功能測試，包含基本分配、保護變更和大記憶體分配測試
- `simple_ioctl_test.c` - 基礎 ioctl 功能測試，直接測試與內核模組的通信
- `memory_test.c` - 基礎記憶體管理測試

### 測試資源

- `dummy_pe_file` - 用於測試的虛擬 PE 文件（用於模擬 PE 文件加載測試）

## 運行測試

要運行測試套件，請確保項目已構建完成：

```bash
make
```

### 運行完整測試套件

```bash
sudo ./tools/test/run_test.sh all
```

### 運行特定類型測試

```bash
sudo ./tools/test/run_test.sh build      # 構建系統測試
sudo ./tools/test/run_test.sh module     # 模組載入測試
sudo ./tools/test/run_test.sh api        # API 功能測試
sudo ./tools/test/run_test.sh integration # 集成測試
```

### 運行單獨的 C 測試程序

```bash
# 加載內核模組
sudo insmod build/ntcore.ko
sudo chmod 666 /dev/ntcore

# 運行各項測試
./build/object_test
./build/safe_memory_test
./build/comprehensive_memory_test
./build/simple_ioctl_test

# 卸載內核模組
sudo rmmod ntcore
```

## 測試內容詳解

### 構建測試 (build_test.sh)

- 驗證構建系統是否正常工作
- 確保所有構建產物都存在於 build 目錄中
- 確保源代碼目錄在構建後保持乾淨

### 模組測試 (module_test.sh)

- 測試內核模組的載入和卸載功能
- 驗證 `/dev/ntcore` 設備是否正確創建
- 確保模組可以正確初始化和清理

### API 測試 (api_test.sh)

- 測試用戶空間組件和 API shim 的基本功能
- 驗證 ntdll_shim 與內核模組的通信

### 集成測試 (integration_test.sh)

- 運行所有測試的綜合測試
- 驗證整個系統的協同工作能力

### 功能測試

- **Object Test**: 測試物件管理系統，包括物件創建和關閉
- **Memory Tests**: 測試記憶體分配、釋放和保護變更功能
- **Ioctl Test**: 測試與內核模組的 ioctl 通信

## 使用方法

所有測試腳本都需要 root 權限來載入內核模組。運行測試前需要先構建項目：

```bash
make
sudo ./tools/test/run_test.sh <test_type>
```

其中 `<test_type>` 可以是：

- `build` - 構建測試
- `module` - 模組測試
- `api` - API 測試
- `integration` - 集成測試
- `all` - 所有測試

## 兼容性

這些測試腳本使用 POSIX shell 語法編寫，兼容各種 shell 環境，包括 bash、zsh、fish 和其他 POSIX 兼容的 shell。

## 注意事項

- 大多數測試需要 root 權限才能載入內核模組
- 在運行測試前，請確保已構建項目（`make`）
- 測試可能會載入和卸載內核模組，請在測試環境中運行
- 測試過程中請確保沒有其他程序正在使用 `/dev/ntcore` 設備
