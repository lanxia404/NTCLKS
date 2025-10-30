# NTCLKS

NTCLKS - A NT-Compatible Linux Kernel Subsystem

## 概述

NTCLKS 是一個基於 Linux 內核的 NT (Windows NT) 相容層項目，目標是讓 Windows PE 格式應用程式能在 Linux 上以原生效能執行，而不依賴 Wine 或虛擬機。

## 項目結構

```bash
NTCLKS/
├── build/                 # 構建產物目錄（由 Makefile 管理，自動忽略）
├── docs/                  # 文檔目錄
├── src/                   # 所有源代碼
│   ├── kernel/            # 內核模組 (ntcore.ko) 源代碼，提供 NT 模型的基本原語
│   ├── userspace/         # 用戶空間組件源代碼
│   │   ├── ntuserd.c      # PE Loader，負責讀取和執行 PE 文件
│   │   └── ntdll_shim.*   # Windows API shim，將 Windows API 請求轉發到內核模組
│   └── include/           # 公共標頭文件
├── tools/                 # 工具和腳本目錄
│   └── test/              # 測試工具和腳本
├── Makefile               # 項目構建文件
├── README.md              # 項目說明文件
├── nt_kernel_compat_design.md # NT 兼容內核子系統設計文檔
└── LICENSE                # 項目授權文件
```

## 構建

要構建項目，請使用以下命令：

```bash
make            # 構建所有組件（構建產物將放在 build/ 目錄中）
make kernel     # 僅構建內核模組
make userspace  # 僅構建用戶空間組件
make clean      # 清理構建產物
```

構建產物將被放置在 `build/` 目錄中，源代碼目錄保持完全乾淨。

## 安裝和測試

要載入內核模組：

```bash
sudo make install   # 構建並載入內核模組
```

要卸載內核模組：

```bash
sudo make uninstall # 卸載內核模組
```

## 測試

項目包含全面的測試套件：

```bash
# 進入測試目錄
cd tools/test

# 運行所有測試
sudo ./run_test.sh all

# 運行特定測試
sudo ./run_test.sh build      # 構建系統測試
sudo ./run_test.sh module     # 模組載入測試
sudo ./run_test.sh api        # API 功能測試
sudo ./run_test.sh integration # 集成測試
```

更多關於測試的詳細信息，請參見 `tools/test/README.md`。

## 狀態

目前項目已實現基本架構和核心功能：

### 內核模組 (ntcore.ko)
- 設備框架和 IOCTL 接口
- NT 記憶體管理功能（VirtualAlloc/Free/Protect）
- NT 物件管理系統（支援進程、線程、事件、互斥鎖、信號量、定時器、文件、記憶體等物件類型）
- 句柄管理系統，使用哈希表實現快速查找
- 記憶體區塊追蹤，防止內存洩漏

### 用戶空間組件
- **PE Loader (ntuserd)** - 實現基本 PE 文件解析功能（DOS/NT 標頭解析）
- **API Shim (ntdll_shim)** - 實現 Windows API 請求轉發功能，包括：
  - NtAllocateVirtualMemory / NtFreeVirtualMemory / NtProtectVirtualMemory
  - NtCreateObject / NtClose
- 錯誤處理和狀態碼轉換
- 內存映射記錄，管理用戶空間和內核空間地址對應關係

### API 支援
當前已實現的 NT API：
- 記憶體管理：`NtAllocateVirtualMemory`, `NtFreeVirtualMemory`, `NtProtectVirtualMemory`
- 物件管理：`NtCreateObject`, `NtClose`

### 測試框架
項目包含多個測試組件：
- 記憶體管理測試
- 物件管理測試
- 系統調用接口測試
- 安全記憶體管理測試

詳細的設計文檔請參見 `nt_kernel_compat_design.md`。

## 貢獻

在提交代碼前，請確保：

1. 所有構建產物都出現在 `build/` 目錄中
2. 源代碼目錄 (`src/`) 在構建後保持乾淨
3. 遵循項目中的代碼風格和結構
4. 測試構建系統仍能正常工作
5. 新增或修改的代碼通過了所有測試

## 授權

本項目根據 LICENSE 文件中描述的條款進行授權。
