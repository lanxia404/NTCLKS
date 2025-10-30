#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntdll_shim.h"

int test_basic_allocation() {
    printf("  Testing basic allocation and deallocation...\n");
    
    PVOID mem_ptr = NULL;
    SIZE_T alloc_size = 4096;  // 4KB
    
    NTSTATUS status = NtAllocateVirtualMemory(
        NULL,                    // ProcessHandle
        &mem_ptr,                // BaseAddress
        0,                       // ZeroBits
        &alloc_size,             // RegionSize
        MEM_COMMIT | MEM_RESERVE,// AllocationType
        PAGE_READWRITE           // Protect
    );
    
    if (status != STATUS_SUCCESS) {
        printf("    FAILED: Basic allocation failed with status: 0x%lx\n", status);
        return 0;
    }
    
    if (mem_ptr == NULL) {
        printf("    FAILED: Allocation returned NULL pointer\n");
        return 0;
    }
    
    // 測試記憶體訪問 (安全方式)
    char *test_mem = (char*)mem_ptr;
    test_mem[0] = 'T';
    test_mem[1] = 'E';
    test_mem[2] = 'S';
    test_mem[3] = 'T';
    test_mem[4] = '\0';
    
    if (strcmp(test_mem, "TEST") != 0) {
        printf("    FAILED: Memory write/read test failed\n");
        return 0;
    }
    
    // 釋放記憶體
    PVOID free_ptr = mem_ptr;
    SIZE_T free_size = 0;
    
    status = NtFreeVirtualMemory(
        NULL,          // ProcessHandle
        &free_ptr,     // BaseAddress
        &free_size,    // RegionSize
        MEM_RELEASE    // FreeType
    );
    
    if (status != STATUS_SUCCESS) {
        printf("    FAILED: Memory free failed with status: 0x%lx\n", status);
        return 0;
    }
    
    printf("    PASSED: Basic allocation and deallocation\n");
    return 1;
}

int test_protection_change() {
    printf("  Testing memory protection change...\n");
    
    PVOID mem_ptr = NULL;
    SIZE_T alloc_size = 4096;  // 4KB
    
    NTSTATUS status = NtAllocateVirtualMemory(
        NULL,                    // ProcessHandle
        &mem_ptr,                // BaseAddress
        0,                       // ZeroBits
        &alloc_size,             // RegionSize
        MEM_COMMIT | MEM_RESERVE,// AllocationType
        PAGE_READWRITE           // Protect
    );
    
    if (status != STATUS_SUCCESS) {
        printf("    FAILED: Initial allocation failed\n");
        return 0;
    }
    
    // 更改保護
    ULONG old_protect = 0;
    SIZE_T protect_size = alloc_size;
    PVOID protect_addr = mem_ptr;
    
    status = NtProtectVirtualMemory(
        NULL,                   // ProcessHandle
        &protect_addr,          // BaseAddress
        &protect_size,          // RegionSize
        PAGE_READONLY,          // NewProtect
        &old_protect           // OldProtect
    );
    
    if (status != STATUS_SUCCESS) {
        printf("    FAILED: Memory protection change failed with status: 0x%lx\n", status);
        // 清理並返回
        NtFreeVirtualMemory(NULL, &mem_ptr, 0, MEM_RELEASE);
        return 0;
    }
    
    if (old_protect != PAGE_READWRITE) {
        printf("    FAILED: Old protection not correctly returned (expected 0x4, got 0x%x)\n", PAGE_READWRITE, old_protect);
        NtFreeVirtualMemory(NULL, &mem_ptr, 0, MEM_RELEASE);
        return 0;
    }
    
    // 測試是否可以讀寫記憶體
    char *test_mem = (char*)mem_ptr;
    test_mem[0] = 'P'; // 在只讀頁面上嘗試寫入可能失敗，但這邊我們只是測試函數調用
    
    // 釋放記憶體
    PVOID free_ptr = mem_ptr;
    SIZE_T free_size = 0;
    
    status = NtFreeVirtualMemory(
        NULL,          // ProcessHandle
        &free_ptr,     // BaseAddress
        &free_size,    // RegionSize
        MEM_RELEASE    // FreeType
    );
    
    if (status != STATUS_SUCCESS) {
        printf("    FAILED: Memory free after protection change failed\n");
        return 0;
    }
    
    printf("    PASSED: Memory protection change\n");
    return 1;
}

int test_large_allocation() {
    printf("  Testing large allocation...\n");
    
    PVOID mem_ptr = NULL;
    SIZE_T alloc_size = 1024 * 1024;  // 1MB
    
    NTSTATUS status = NtAllocateVirtualMemory(
        NULL,                    // ProcessHandle
        &mem_ptr,                // BaseAddress
        0,                       // ZeroBits
        &alloc_size,             // RegionSize
        MEM_COMMIT | MEM_RESERVE,// AllocationType
        PAGE_READWRITE           // Protect
    );
    
    if (status != STATUS_SUCCESS) {
        printf("    FAILED: Large allocation failed with status: 0x%lx\n", status);
        return 0;
    }
    
    if (mem_ptr == NULL) {
        printf("    FAILED: Large allocation returned NULL pointer\n");
        return 0;
    }
    
    // 測試記憶體訪問
    char *test_mem = (char*)mem_ptr;
    test_mem[0] = 'L';
    test_mem[1024*1024 - 1] = 'E';  // 在分配區域的末尾寫入
    
    if (test_mem[0] != 'L') {
        printf("    FAILED: Large memory access test failed\n");
        NtFreeVirtualMemory(NULL, &mem_ptr, 0, MEM_RELEASE);
        return 0;
    }
    
    // 釋放記憶體
    PVOID free_ptr = mem_ptr;
    SIZE_T free_size = 0;
    
    status = NtFreeVirtualMemory(
        NULL,          // ProcessHandle
        &free_ptr,     // BaseAddress
        &free_size,    // RegionSize
        MEM_RELEASE    // FreeType
    );
    
    if (status != STATUS_SUCCESS) {
        printf("    FAILED: Large memory free failed\n");
        return 0;
    }
    
    printf("    PASSED: Large allocation\n");
    return 1;
}

int main() {
    printf("NTCLKS Comprehensive Memory Management Test\n");
    printf("===========================================\n");
    
    // 初始化 ntdll shim
    if (init_ntdll_shim() != 0) {
        printf("FAILED: Could not initialize ntdll shim\n");
        return 1;
    }
    
    printf("Ntdll shim initialized successfully\n\n");
    
    int tests_run = 0;
    int tests_passed = 0;
    
    // 運行所有測試
    tests_run++;
    if (test_basic_allocation()) tests_passed++;
    
    tests_run++;
    if (test_protection_change()) tests_passed++;
    
    tests_run++;
    if (test_large_allocation()) tests_passed++;
    
    // 輸出結果
    printf("\nTest Results: %d/%d tests passed\n", tests_passed, tests_run);
    
    if (tests_passed == tests_run) {
        printf("ALL TESTS PASSED! Memory management functions are working correctly.\n");
    } else {
        printf("SOME TESTS FAILED! There may be issues with memory management functions.\n");
    }
    
    // 清理
    cleanup_ntdll_shim();
    printf("\nComprehensive memory management test completed\n");
    
    return (tests_passed == tests_run) ? 0 : 1;
}