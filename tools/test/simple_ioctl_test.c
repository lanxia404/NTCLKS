#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>

// NT 記憶體管理 ioctl 命令
#define NT_SYSCALL_BASE 0x1000
#define NT_VIRTUAL_ALLOC  _IOWR(NT_SYSCALL_BASE, 3, struct nt_mem_info)
#define NT_VIRTUAL_FREE   _IOWR(NT_SYSCALL_BASE, 4, struct nt_mem_info)
#define NT_VIRTUAL_PROTECT _IOWR(NT_SYSCALL_BASE, 5, struct nt_protect_info)

// NT 資料結構定義
struct nt_mem_info {
    uint64_t addr;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
    uint64_t result_addr;
};

struct nt_protect_info {
    uint64_t addr;
    uint64_t size;
    uint32_t new_protect;
    uint32_t old_protect;
};

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
#define MEM_COMMIT    0x1000
#define MEM_RESERVE   0x2000
#define MEM_DECOMMIT  0x4000
#define MEM_RELEASE   0x8000

int main() {
    int fd;
    struct nt_mem_info mem_info;
    int result;
    
    printf("Direct ioctl test\n");
    printf("==================\n");
    
    // 打開設備
    fd = open("/dev/ntcore", O_RDWR);
    if (fd < 0) {
        perror("Failed to open /dev/ntcore");
        return 1;
    }
    
    printf("Device opened successfully\n");
    
    // 準備記憶體分配請求
    mem_info.addr = 0;  // 任意地址
    mem_info.size = 4096;  // 4KB
    mem_info.protect = PAGE_READWRITE;
    mem_info.type = MEM_COMMIT | MEM_RESERVE;
    mem_info.result_addr = 0;
    
    printf("Calling ioctl for VirtualAlloc...\n");
    
    // 執行 ioctl 請求
    result = ioctl(fd, NT_VIRTUAL_ALLOC, &mem_info);
    
    printf("ioctl result: %d\n", result);
    if (result == 0) {
        printf("Allocation successful! Returned address: 0x%lx\n", mem_info.result_addr);
    } else {
        printf("Allocation failed!\n");
    }
    
    close(fd);
    
    printf("Direct test completed\n");
    return 0;
}