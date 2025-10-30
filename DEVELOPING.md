# NTCLKS 開發指南

本指南介紹如何開發和擴展 NTCLKS 專案。

## 項目結構

```bash
NTCLKS/
├── build/                 # 構建產物目錄
├── docs/                  # 文檔目錄
├── src/                   # 所有源代碼
│   ├── kernel/            # 內核模組源代碼
│   ├── userspace/         # 用戶空間組件源代碼
│   └── include/           # 公共標頭文件
├── tools/                 # 工具和腳本目錄
│   └── test/              # 測試工具和腳本
├── Makefile               # 項目構建文件
└── README.md              # 項目說明文件
```

## 編譯和構建

要構建項目，使用以下命令：

```bash
make            # 構建所有組件
make kernel     # 僅構建內核模組
make userspace  # 僅構建用戶空間組件
make clean      # 清理構建產物
```

## 內核模組開發

### 添加新的 NT API

要添加新的 NT API 函數：

1. 在 `src/kernel/ntcore.c` 中添加 ioctl 命令定義
2. 實現對應的處理函數
3. 在 `ntcore_ioctl` 函數中添加命令處理情況
4. 在 `src/userspace/ntdll_shim.h` 中添加函數原型
5. 在 `src/userspace/ntdll_shim.c` 中實現用戶空間函數

#### 示例：添加新的記憶體管理 API

假設要添加 `NtQueryVirtualMemory` 函數：

1. 在 `ntcore.c` 中添加 ioctl 定義：
```c
#define NT_QUERY_VIRTUAL_MEMORY _IOWR(NT_SYSCALL_BASE, 8, struct nt_mem_query_info)
```

2. 定義資料結構：
```c
struct nt_mem_query_info {
    uint64_t addr;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
    uint64_t result_addr;  // 用於返回分配的地址
};
```

3. 實現處理函數：
```c
static long nt_query_virtual_memory(struct nt_mem_query_info *info) {
    // 實現查詢邏輯
    // ...
    return 0;
}
```

4. 在 `ntcore_ioctl` 中添加處理情況：
```c
case NT_QUERY_VIRTUAL_MEMORY:
    if (copy_from_user(&query_info, argp, sizeof(query_info))) {
        return -EFAULT;
    }
    result = nt_query_virtual_memory(&query_info);
    if (result == 0) {
        if (copy_to_user(argp, &query_info, sizeof(query_info))) {
            return -EFAULT;
        }
    }
    break;
```

5. 在 `ntdll_shim.h` 中添加函數原型：
```c
NTSTATUS NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PULONG Buffer
);
```

6. 在 `ntdll_shim.c` 中實現用戶空間函數：
```c
NTSTATUS NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PULONG Buffer
) {
    struct nt_mem_query_info query_info;
    int result;
    
    if (ntcore_fd < 0) return STATUS_UNSUCCESSFUL;
    
    query_info.addr = (uint64_t)BaseAddress;
    // ... 初始化其他欄位
    
    result = ioctl(ntcore_fd, NT_QUERY_VIRTUAL_MEMORY, &query_info);
    if (result != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // ... 處理返回結果
    return STATUS_SUCCESS;
}
```

### 記憶體管理擴展

當前實現支援：

- `NtAllocateVirtualMemory` - 記憶體分配
- `NtFreeVirtualMemory` - 記憶體釋放
- `NtProtectVirtualMemory` - 記憶體保護變更

### 物件管理系統

物件管理系統支援：

- 物件創建和關閉 (`NtCreateObject`, `NtClose`)
- 物件類型：進程、線程、區段、事件、互斥鎖、信號量、定時器、文件、記憶體
- 哈希表索引以實現快速查找
- 句柄管理系統，支援引用計數

#### 物件系統擴展示例

當添加新的物件類型時：

1. 在 `ntcore.c` 中擴展 `NT_OBJECT_TYPE` 枚舉：
```c
typedef enum _NT_OBJECT_TYPE {
    NT_TYPE_UNKNOWN = 0,
    NT_TYPE_PROCESS,
    NT_TYPE_THREAD,
    // ... 現有類型
    NT_TYPE_NEW_TYPE,  // 新增類型
} NT_OBJECT_TYPE;
```

2. 在物件處理函數中加入新類型的處理邏輯

3. 在用戶空間相應更新物件創建和管理邏輯

## 用戶空間組件

### ntdll_shim

ntdll_shim 組件負責將 NT API 調用轉發到內核模組。實現包括：

- 參數轉換
- ioctl 調用
- 錯誤處理
- 狀態碼轉換
- 內存映射記錄，管理用戶空間和內核空間地址對應關係

## 測試

運行測試前請確保：

1. 內核模組已構建
2. 具有 root 權限
3. 以前的測試實例已清理

測試命令：

```bash
# 構建測試
make

# 加載內核模組
sudo insmod build/ntcore.ko
sudo chmod 666 /dev/ntcore

# 運行測試
./build/object_test
./build/safe_memory_test

# 卸載內核模組
sudo rmmod ntcore
```

## 代碼風格

- 使用 Linux 內核代碼風格（對於內核部分）
- 用戶空間代碼使用一致的縮排和命名約定
- 添加適當的註釋，尤其是對複雜邏輯

## 調試技巧

- 使用 `dmesg` 查看內核消息
- 檢查 `/dev/ntcore` 設備是否正確創建
- 確保內核模組版本與用戶空間組件匹配
  