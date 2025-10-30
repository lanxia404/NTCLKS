#ifndef _NTDLL_SHIM_H_
#define _NTDLL_SHIM_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// ntdll shim 虛擬實現
// 這些函數將實際的 Windows API 請求轉發到內核模組

#define NT_DEVICE "/dev/ntcore"

// ioctl 命令定義
#define NT_SYSCALL_BASE 0x1000
#define NT_VIRTUAL_ALLOC  _IOWR(NT_SYSCALL_BASE, 3, struct nt_mem_info)
#define NT_VIRTUAL_FREE   _IOWR(NT_SYSCALL_BASE, 4, struct nt_mem_info)
#define NT_VIRTUAL_PROTECT _IOWR(NT_SYSCALL_BASE, 5, struct nt_protect_info)

// 記憶體資訊結構
struct nt_mem_info {
    uint64_t addr;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
    uint64_t result_addr;  // 用於返回分配的地址
};

struct nt_protect_info {
    uint64_t addr;
    uint64_t size;
    uint32_t new_protect;
    uint32_t old_protect;
};

// 全局變量宣告
extern int ntcore_fd;

// 基本型別定義 (與 Windows 相容)
typedef void VOID;
typedef long NTSTATUS;
typedef long LONG;
typedef void* HANDLE;
typedef void* PVOID;
typedef void* LPVOID;
typedef const void* LPCVOID;
typedef char* LPSTR;
typedef const char* LPCSTR;
typedef unsigned long DWORD;
typedef unsigned long ULONG;
typedef unsigned long LONGLONG;
typedef unsigned short WORD;
typedef unsigned short USHORT;
typedef unsigned char BYTE;
typedef char CHAR;
typedef unsigned char UCHAR;
typedef char* PCHAR;
typedef unsigned short WCHAR;
typedef unsigned short* PWCH;
typedef unsigned long ULONG_PTR;
typedef size_t SIZE_T;
typedef SIZE_T* PSIZE_T;
typedef ULONG* PULONG;
typedef PVOID* PVOID_PTR;
typedef ULONG ACCESS_MASK;

// Windows 標記定義
#define _In_
#define _Out_
#define _In_opt_
#define _Out_opt_
#define _Inout_
#define _Inout_opt_

// 全局變量宣告
extern int ntcore_fd;
typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef VOID(*PIO_APC_ROUTINE) (
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );
typedef struct _LARGE_INTEGER {
    union {
        struct {
            ULONG LowPart;
            LONG HighPart;
        } DUMMYSTRUCTNAME;
        struct {
            ULONG LowPart;
            LONG HighPart;
        } u;
        LONGLONG QuadPart;
    } DUMMYUNIONNAME;
} LARGE_INTEGER, *PLARGE_INTEGER;

// 指標型別
typedef PVOID *PHANDLE;
typedef PVOID *PVOID_PTR;
typedef ULONG *PULONG_PTR;
typedef DWORD *PDWORD;
typedef BYTE *PBYTE;

// 狀態碼定義
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_INVALID_PARAMETER 0xC000000D
#define STATUS_ACCESS_VIOLATION 0xC0000005

// 記憶體保護標誌
#define PAGE_NOACCESS 0x01
#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_WRITECOPY 0x08
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_EXECUTE_WRITECOPY 0x80

// 記憶體分配類型
#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define MEM_DECOMMIT 0x4000
#define MEM_RELEASE 0x8000

// NT 物件類型定義
typedef enum _NT_OBJECT_TYPE {
    NT_TYPE_UNKNOWN = 0,
    NT_TYPE_PROCESS = 1,
    NT_TYPE_THREAD = 2,
    NT_TYPE_SECTION = 3,
    NT_TYPE_EVENT = 4,
    NT_TYPE_MUTANT = 5,
    NT_TYPE_SEMAPHORE = 6,
    NT_TYPE_TIMER = 7,
    NT_TYPE_FILE = 8,
    NT_TYPE_MEMORY = 9,      // 用於記憶體管理物件
} NT_OBJECT_TYPE;

// 物件管理相關 ioctl 命令
#define NT_CREATE_OBJECT  _IOWR(NT_SYSCALL_BASE, 6, struct _NT_OBJECT_CREATE_INFO)
#define NT_CLOSE_OBJECT   _IOWR(NT_SYSCALL_BASE, 7, struct _NT_OBJECT_CLOSE_INFO)

// 物件創建資訊結構
typedef struct _NT_OBJECT_CREATE_INFO {
    NT_OBJECT_TYPE type;
    uint64_t initial_params;
    uint64_t handle;  // 輸出：創建的物件句柄
} NT_OBJECT_CREATE_INFO, *PNT_OBJECT_CREATE_INFO;

// 物件關閉資訊結構
typedef struct _NT_OBJECT_CLOSE_INFO {
    uint64_t handle;
} NT_OBJECT_CLOSE_INFO, *PNT_OBJECT_CLOSE_INFO;

// NT API 函數原型 (shim 實現)
NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

NTSTATUS NtReadFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

NTSTATUS NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

NTSTATUS NtCreateObject(
    POBJECT_ATTRIBUTES ObjectAttributes,
    NT_OBJECT_TYPE ObjectType,
    PVOID ObjectBody,
    ACCESS_MASK GrantedAccess,
    HANDLE *OutHandle
);

NTSTATUS NtClose(
    HANDLE Handle
);

// 初始化和清理函數
int init_ntdll_shim();
void cleanup_ntdll_shim();

#endif // _NTDLL_SHIM_H_