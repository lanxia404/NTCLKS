#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntdll_shim.h"

int main() {
    printf("NTCLKS Object Management Test\n");
    printf("============================\n");
    
    // 初始化 ntdll shim
    if (init_ntdll_shim() != 0) {
        printf("Failed to initialize ntdll shim\n");
        return 1;
    }
    
    printf("Ntdll shim initialized successfully\n");
    
    // 測試 1: 創建記憶體物件
    printf("\nTest 1: Create memory object\n");
    HANDLE mem_handle = NULL;
    NTSTATUS status = NtCreateObject(
        NULL,                  // ObjectAttributes
        NT_TYPE_MEMORY,        // ObjectType  
        NULL,                  // ObjectBody
        0,                     // GrantedAccess
        &mem_handle            // OutHandle
    );
    
    if (status == STATUS_SUCCESS && mem_handle != NULL) {
        printf("  ✓ Memory object created successfully with handle: %p\n", mem_handle);
    } else {
        printf("  ✗ Memory object creation failed with status: 0x%lx\n", status);
        cleanup_ntdll_shim();
        return 1;
    }
    
    // 測試 2: 創建事件物件
    printf("\nTest 2: Create event object\n");
    HANDLE event_handle = NULL;
    status = NtCreateObject(
        NULL,                  // ObjectAttributes
        NT_TYPE_EVENT,         // ObjectType
        NULL,                  // ObjectBody
        0,                     // GrantedAccess
        &event_handle          // OutHandle
    );
    
    if (status == STATUS_SUCCESS && event_handle != NULL) {
        printf("  ✓ Event object created successfully with handle: %p\n", event_handle);
    } else {
        printf("  ✗ Event object creation failed with status: 0x%lx\n", status);
        // 繼續執行，即使這個測試失敗
    }
    
    // 測試 3: 關閉物件
    printf("\nTest 3: Close memory object\n");
    status = NtClose(mem_handle);
    if (status == STATUS_SUCCESS) {
        printf("  ✓ Memory object closed successfully\n");
    } else {
        printf("  ✗ Memory object close failed with status: 0x%lx\n", status);
    }
    
    // 測試 4: 關閉事件物件
    if (event_handle != NULL) {
        printf("\nTest 4: Close event object\n");
        status = NtClose(event_handle);
        if (status == STATUS_SUCCESS) {
            printf("  ✓ Event object closed successfully\n");
        } else {
            printf("  ✗ Event object close failed with status: 0x%lx\n", status);
        }
    }
    
    // 清理
    cleanup_ntdll_shim();
    printf("\nObject management test completed\n");
    
    return 0;
}