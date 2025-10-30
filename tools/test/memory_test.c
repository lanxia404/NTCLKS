#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntdll_shim.h"



int main() {
    printf("NTCLKS Memory Management Test\n");
    printf("============================\n");
    
    // 初始化 ntdll shim
    if (init_ntdll_shim() != 0) {
        printf("Failed to initialize ntdll shim\n");
        return 1;
    }
    
    printf("Ntdll shim initialized successfully\n");
    
    // 測試 1: 基本記憶體分配
    PVOID mem_ptr = NULL;
    SIZE_T alloc_size = 4096;  // 4KB
    
    printf("\nTest 1: Basic memory allocation\n");
    NTSTATUS status = NtAllocateVirtualMemory(
        NULL,                    // ProcessHandle
        &mem_ptr,                // BaseAddress
        0,                       // ZeroBits
        &alloc_size,             // RegionSize
        MEM_COMMIT | MEM_RESERVE,// AllocationType
        PAGE_READWRITE           // Protect
    );
    
    if (status == STATUS_SUCCESS) {
        printf("  ✓ Memory allocated successfully at %p, size: %zu\n", mem_ptr, alloc_size);
    } else {
        printf("  ✗ Memory allocation failed with status: 0x%lx\n", status);
        cleanup_ntdll_shim();
        return 1;
    }
    
    // 測試 2: 寫入和讀取數據
    printf("\nTest 2: Write and read test\n");
    if (mem_ptr) {
        // 寫入測試數據
        char *test_mem = (char*)mem_ptr;
        test_mem[0] = 'H';
        test_mem[1] = 'i';
        test_mem[2] = '\0';
        
        printf("  ✓ Wrote data to allocated memory: '%s'\n", test_mem);
    }
    
    // 測試 3: 更改記憶體保護
    printf("\nTest 3: Change memory protection\n");
    ULONG old_protect = 0;
    SIZE_T protect_size = 4096;
    PVOID protect_addr = mem_ptr;
    
    status = NtProtectVirtualMemory(
        NULL,                   // ProcessHandle
        &protect_addr,          // BaseAddress
        &protect_size,          // RegionSize
        PAGE_READONLY,          // NewProtect
        &old_protect           // OldProtect
    );
    
    if (status == STATUS_SUCCESS) {
        printf("  ✓ Memory protection changed, old: 0x%x, new: 0x%x\n", old_protect, PAGE_READONLY);
    } else {
        printf("  ✗ Memory protection change failed with status: 0x%lx\n", status);
    }
    
    // 測試 4: 釋放記憶體
    printf("\nTest 4: Free memory\n");
    PVOID free_ptr = mem_ptr;
    SIZE_T free_size = 0;
    
    status = NtFreeVirtualMemory(
        NULL,          // ProcessHandle
        &free_ptr,     // BaseAddress
        &free_size,    // RegionSize
        MEM_RELEASE    // FreeType
    );
    
    if (status == STATUS_SUCCESS) {
        printf("  ✓ Memory freed successfully\n");
    } else {
        printf("  ✗ Memory free failed with status: 0x%lx\n", status);
    }
    
    // 清理
    cleanup_ntdll_shim();
    printf("\nMemory management test completed\n");
    
    return 0;
}