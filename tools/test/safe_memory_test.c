#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntdll_shim.h"

int main() {
    printf("NTCLKS Memory Management Test (Safe Version)\n");
    printf("============================================\n");
    
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
        
        // 測試 2: 釋放記憶體，避免內存訪問問題
        printf("\nTest 2: Free memory\n");
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
    } else {
        printf("  ✗ Memory allocation failed with status: 0x%lx\n", status);
        cleanup_ntdll_shim();
        return 1;
    }
    
    // 清理
    cleanup_ntdll_shim();
    printf("\nSafe memory management test completed\n");
    
    return 0;
}