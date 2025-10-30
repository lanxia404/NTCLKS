# NT-Compatible Linux Kernel Subsystem Design Draft

## 目標

建立一套基於 Linux 內核的 NT 相容層，以 Windows 10/11 為目標兼容版本，目的是能夠以原生效能執行大部分 Windows 用戶端應用程式，不依賴 Wine 或 VM。該層將針對 NT 內核基礎模型進行實作，使 PE 檔案能在 Linux 上直接被讀取和執行。

## 主體架構

### 1. 內核 NT 兼容模組 (ntcore.ko)

- Linux kernel module，提供 NT 模型的基本原諒：執行緒、記憶體、物件管理、同步原諒、I/O 操作等。
- 在 `/dev/ntcore` 建立 ioctl 介面，接收來自 userland ntdll shim 的 NT 命令。
- 與 Linux task_struct/mm_struct/filesystem 等機制對應，提供 NT 處理流程、處理緒、處理區間資源映射。

### 2. 用戶端 PE Loader (ntuserd)

- 讀取 PE32/PE32+ 檔案，進行資料模組讀入與 Section Mapping。
- 構建匯入表與 ntdll stub，使 Windows API 命令能轉變為 ioctl 命令發送到 /dev/ntcore。
- 負責管理 DLL 加載、TLS 處理、執行進入點。

### 3. ntdll / Win32 API Shim

- ntdll.dll 實作：接收用戶端命令，轉為 NT 級命令給 ntcore.ko。
- kernel32/user32/gdi32 shell shim：依需實作此層轉接，以取得執行與 GUI 兼容。

### 4. IPC 語意定義

- 執行 ioctl(命令編號, struct nt_syscall_packet)，由 userland stub 傳遞至 kernel 模組。
- 模組回傳 NTSTATUS 與返回資料。

## 實作步驟

### Sprint 1 — PE Loader + mmap (已完成)

- 完成對 PE header 解析、section mapping 、import resolution 的 userland 實作。
- ntcore.ko 提供執行 VirtualAlloc/Free/Protect ioctl。
- 實現基本記憶體管理功能 (NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory)
- 實現物件管理系統基礎 (NtCreateObject, NtClose)
- 建立用戶空間與內核空間通信框架

### Sprint 2 — Process / Thread (進行中)

- NtCreateProcess/NtCreateThread 實作：映射到 clone()/pthread 與 task_struct 資料結構。
- handle table 與 PID mapping 定義與執行。
- 實現進程和線程的生命週期管理
- 實現基本同步原語（事件、互斥鎖、信號量）

### Sprint 3 — File I/O

- NtCreateFile/NtReadFile/NtWriteFile 映射到 Linux VFS。
- 路徑轉接：C:\ -> /mnt/c/ 類似路徑映射器。
- 實現文件系統相關的 NT API

### Sprint 4 — Synchronization + Exception

- KeWaitForSingleObject / KeSetEvent -> futex 基礎實作。
- 執行 SEH -> Linux signal handler + userland SEH dispatcher。

### Sprint 5 — I/O Completion + APC/DPC

- 接入 io_uring 設計，提供高效非阻塞 I/O，轉接至 NT I/O completion model。

## 核心 Mapping 表

| NT 概念 | Linux 對應 | 備註 |
|----------------|-------------------|--------------|
| Process | task_struct | 執行程式執行體 |
| Thread | clone()/pthread | Linux thread group 映射 |
| Handle Table | 內核 table + fd | 結合內核描述符與引用計數 |
| Virtual Memory | mm_struct + mmap | PAGE_PROT 對應表 |
| File I/O | VFS | 通用檔操作 |
| Event/Mutex | futex | wait_queue 或 spinlock 代理 |
| IRP | work_struct | I/O 作業序列 |
| Timer/APC | hrtimer + workqueue | 時間與非同步處理 |

## 圖形體系構 (ASCII)

```txt
+---------------------------------------------+
| User Space                                  |
|  PE Loader / ntdll.dll stub / kernel32.dll  |
+-------------------------|-------------------+
                          |
                 ioctl / netlink / shared mem
                          |
+-------------------------V-------------------+
| Linux Kernel (ntcore.ko)                   |
|  - NtProcess / NtThread Manager            |
|  - Virtual Memory Manager                  |
|  - I/O Subsystem (VFS + io_uring)          |
|  - Sync Manager (futex / waitqueue)        |
|  - Object / Handle Table                   |
+---------------------------------------------+
                          |
                 Linux kernel primitives
                          |
+---------------------------------------------+
| Linux Core (task_struct, mm_struct, VFS...) |
+---------------------------------------------+
```

## 第一階段目標 (MVP)

- 可執行 console 類 Win32 應用 (HelloWorld.exe, cmd-lite.exe)
- 支援基本檔案 I/O、執行程式後台執行、執行緒、執行終止
- 記憶體分配上下文兼容

## 發展方向

1. GUI Subsystem: 接入 Wayland/端口設計，針對 user32/gdi32 執行程式建立層。  
2. DirectX 兼容：依賴 DXVK/Vulkan layer 轉接。  
3. Driver Stack：接入 Linux 檔形馬達變接口，用於試驗移植 Windows 驅動。  
4. 安全性：通過 namespace/cgroup 隔離、SELinux policy 限制權限。  
5. 效能優化：突出熱路徑避免次位系統呼叫或通訊。

## 開源與版權

- 依照 MIT 或 LGPLv2.1 發佈，避免法律與商業版權衝突。
- 可參考 ReactOS/Wine 源碼，但不能直接複製其實現程式。

## 關鍵資源與參考

- ReactOS ntoskrnl 檔案架構。
- Wine ntdll/kernel32 實作資料源。
- Linux kernel task_struct/mm_struct/vfs 源碼以及 LXR 參考查詢。
