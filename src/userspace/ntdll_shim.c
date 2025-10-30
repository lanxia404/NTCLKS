// ntdll.dll 虛擬實現 - 將 Windows API 請求轉發到內核模組
// 這是一個簡化的骨架，展示了如何將 API 請求通過 ioctl 發送到內核

#include "ntdll_shim.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

// 全局變量：內核設備文件描述符
int ntcore_fd = -1;

// 內存映射記錄結構
typedef struct _MEMORY_MAPPING {
    uint64_t kernel_addr;  // 內核分配的地址
    void* user_addr;       // 用戶空間對應地址
    size_t size;           // 大小
    struct _MEMORY_MAPPING* next;  // 鏈表指針
} MEMORY_MAPPING;

static MEMORY_MAPPING* memory_mappings = NULL;

// 添加內存映射記錄
static void add_memory_mapping(uint64_t kernel_addr, void* user_addr, size_t size) {
    MEMORY_MAPPING* mapping = malloc(sizeof(MEMORY_MAPPING));
    if (!mapping) return;
    
    mapping->kernel_addr = kernel_addr;
    mapping->user_addr = user_addr;
    mapping->size = size;
    mapping->next = memory_mappings;
    memory_mappings = mapping;
}

// 根據用戶地址查找內核地址
static uint64_t find_kernel_addr(void* user_addr) {
    MEMORY_MAPPING* current = memory_mappings;
    while (current) {
        if (current->user_addr == user_addr) {
            return current->kernel_addr;
        }
        current = current->next;
    }
    return 0;
}

// 清理內存映射記錄
static void remove_memory_mapping(void* user_addr) {
    MEMORY_MAPPING** current = &memory_mappings;
    while (*current) {
        if ((*current)->user_addr == user_addr) {
            MEMORY_MAPPING* to_remove = *current;
            *current = (*current)->next;
            free(to_remove);
            return;
        }
        current = &(*current)->next;
    }
}



// 初始化函數
int init_ntdll_shim() {
    ntcore_fd = open("/dev/ntcore", O_RDWR);
    if (ntcore_fd < 0) {
        perror("Failed to open /dev/ntcore");
        return -1;
    }
    printf("ntdll shim initialized, device fd: %d\n", ntcore_fd);
    return 0;
}

// 清理函數
void cleanup_ntdll_shim() {
    if (ntcore_fd >= 0) {
        close(ntcore_fd);
        ntcore_fd = -1;
    }
    printf("ntdll shim cleaned up\n");
}

// 模擬實際的 NT API 實現
NTSTATUS NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
) {
    // TODO: 通過 ioctl 發送到內核模組
    printf("NtCreateFile called\n");
    if (ntcore_fd < 0) return STATUS_UNSUCCESSFUL;
    
    // 模擬 ioctl 調用
    // ioctl(ntcore_fd, NT_CREATE_FILE, &params);
    
    return STATUS_SUCCESS;
}

// 實際的 shim 函數實現
NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    struct nt_mem_info mem_info;
    int result;
    void *user_mem = NULL;
    
    if (ntcore_fd < 0) return STATUS_UNSUCCESSFUL;
    
    if (!BaseAddress || !RegionSize) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化記憶體資訊結構
    mem_info.addr = (uint64_t)*BaseAddress;
    mem_info.size = *RegionSize;
    mem_info.protect = Protect;
    mem_info.type = AllocationType;
    mem_info.result_addr = 0;
    
    // 執行 ioctl 調用到內核模組
    result = ioctl(ntcore_fd, NT_VIRTUAL_ALLOC, &mem_info);
    if (result != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 重要：不要直接使用內核返回的地址，而是分配用戶空間的記憶體
    // 這防止段錯誤問題，因為內核地址不能在用戶空間直接訪問
    user_mem = malloc(mem_info.size);
    if (!user_mem) {
        // 如果用戶空間分配失敗，嘗試釋放內核記憶體
        struct nt_mem_info free_info = {0};
        free_info.addr = mem_info.result_addr;
        free_info.size = 0;
        free_info.type = MEM_RELEASE;
        ioctl(ntcore_fd, NT_VIRTUAL_FREE, &free_info);
        return STATUS_UNSUCCESSFUL;
    }
    
    // 添加到內存映射記錄，以便後續釋放和保護更改使用正確的地址
    add_memory_mapping(mem_info.result_addr, user_mem, mem_info.size);
    
    // 更新輸出參數 - 使用用戶空間地址而不是內核地址
    *BaseAddress = user_mem;
    *RegionSize = mem_info.size;
    
    printf("NtAllocateVirtualMemory: allocated 0x%lx bytes at user addr %p\n", 
           (unsigned long)mem_info.size, user_mem);
    
    return STATUS_SUCCESS;
}

NTSTATUS NtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
) {
    struct nt_mem_info mem_info;
    int result;
    void *user_addr = *BaseAddress;
    uint64_t kernel_addr;
    
    if (ntcore_fd < 0) return STATUS_UNSUCCESSFUL;
    
    if (!BaseAddress) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 查找對應的內核地址
    kernel_addr = find_kernel_addr(user_addr);
    if (kernel_addr == 0) {
        // 如果找不到映射，嘗試直接使用用戶地址值（這是最後的備用）
        kernel_addr = (uint64_t)(unsigned long)user_addr;
        printf("Warning: Could not find kernel address mapping, using user address as kernel address\n");
    }
    
    // 初始化記憶體資訊結構
    mem_info.addr = kernel_addr;
    mem_info.size = RegionSize ? *RegionSize : 0;
    mem_info.type = FreeType;
    
    // 執行 ioctl 調用到內核模組
    result = ioctl(ntcore_fd, NT_VIRTUAL_FREE, &mem_info);
    if (result != 0) {
        // 內核調用失敗，但我們仍釋放用戶空間內存
        printf("Warning: NtFreeVirtualMemory ioctl failed, but freeing user memory\n");
    }
    
    // 釋放用戶空間分配的內存
    if (user_addr) {
        free(user_addr);
        remove_memory_mapping(user_addr);
    }
    
    // 更新輸出參數
    if (RegionSize) {
        *RegionSize = mem_info.size;
    }
    *BaseAddress = NULL;
    
    printf("NtFreeVirtualMemory: freed memory at user addr %p, kernel addr 0x%lx\n", 
           user_addr, kernel_addr);
    
    return STATUS_SUCCESS;
}

NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    struct nt_protect_info protect_info;
    int result;
    void *user_addr = *BaseAddress;
    uint64_t kernel_addr;
    
    if (ntcore_fd < 0) return STATUS_UNSUCCESSFUL;
    
    if (!BaseAddress || !RegionSize || !OldProtect) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 查找對應的內核地址
    kernel_addr = find_kernel_addr(user_addr);
    if (kernel_addr == 0) {
        // 如果找不到映射，使用用戶地址值
        kernel_addr = (uint64_t)(unsigned long)user_addr;
        printf("Warning: Could not find kernel address mapping for protect\n");
    }
    
    // 初始化保護資訊結構
    protect_info.addr = kernel_addr;
    protect_info.size = *RegionSize;
    protect_info.new_protect = NewProtect;
    protect_info.old_protect = 0;
    
    // 執行 ioctl 調用到內核模組
    result = ioctl(ntcore_fd, NT_VIRTUAL_PROTECT, &protect_info);
    if (result != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 更新輸出參數
    *OldProtect = protect_info.old_protect;
    
    printf("NtProtectVirtualMemory: changed protection at user addr %p (kernel 0x%lx) from 0x%x to 0x%x\n", 
           user_addr, kernel_addr, protect_info.old_protect, NewProtect);
    
    return STATUS_SUCCESS;
}

// NT 物件創建函數
NTSTATUS NtCreateObject(
    POBJECT_ATTRIBUTES ObjectAttributes,
    NT_OBJECT_TYPE ObjectType,
    PVOID ObjectBody,
    ACCESS_MASK GrantedAccess,
    HANDLE *OutHandle
) {
    NT_OBJECT_CREATE_INFO obj_info;
    int result;
    
    if (ntcore_fd < 0) return STATUS_UNSUCCESSFUL;
    
    if (!OutHandle) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化物件創建資訊結構
    obj_info.type = ObjectType;
    obj_info.initial_params = (uint64_t)ObjectBody; // 作為初始參數傳遞
    obj_info.handle = 0;
    
    // 執行 ioctl 調用到內核模組
    result = ioctl(ntcore_fd, NT_CREATE_OBJECT, &obj_info);
    if (result != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // 返回創建的句柄
    *OutHandle = (HANDLE)obj_info.handle;
    
    printf("NtCreateObject: created object with handle 0x%p (type: %d)\n", 
           (void*)obj_info.handle, ObjectType);
    
    return STATUS_SUCCESS;
}

// NT 物件關閉函數
NTSTATUS NtClose(
    HANDLE Handle
) {
    NT_OBJECT_CLOSE_INFO obj_info;
    int result;
    
    if (ntcore_fd < 0) return STATUS_UNSUCCESSFUL;
    
    if (!Handle) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // 初始化物件關閉資訊結構
    obj_info.handle = (uint64_t)Handle;
    
    // 執行 ioctl 調用到內核模組
    result = ioctl(ntcore_fd, NT_CLOSE_OBJECT, &obj_info);
    if (result != 0) {
        return STATUS_UNSUCCESSFUL;
    }
    
    printf("NtClose: closed object with handle 0x%p\n", Handle);
    
    return STATUS_SUCCESS;
}