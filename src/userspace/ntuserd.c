#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define NT_DEVICE "/dev/ntcore"
#define NT_SYSCALL_BASE 0x1000

// NT 系統呼叫命令定義
#define NT_CREATE_PROCESS _IOWR(NT_SYSCALL_BASE, 1, struct nt_process_info)
#define NT_CREATE_THREAD  _IOWR(NT_SYSCALL_BASE, 2, struct nt_thread_info)
#define NT_VIRTUAL_ALLOC  _IOWR(NT_SYSCALL_BASE, 3, struct nt_mem_info)
#define NT_VIRTUAL_FREE   _IOWR(NT_SYSCALL_BASE, 4, struct nt_mem_info)

// NT 資料結構定義
struct nt_process_info {
    char path[256];
    unsigned long pid;
    unsigned long base_addr;
};

struct nt_thread_info {
    unsigned long tid;
    unsigned long start_addr;
    unsigned long param;
};

struct nt_mem_info {
    void *addr;
    size_t size;
    unsigned long protect;
    unsigned long type;
};

// PE 檔案結構定義
typedef struct {
    unsigned short e_magic;      // Magic number
    unsigned short e_cblp;       // Bytes on last page of file
    unsigned short e_cp;         // Pages in file
    unsigned short e_crlc;       // Relocations
    unsigned short e_cparhdr;    // Size of header in paragraphs
    unsigned short e_minalloc;   // Minimum extra paragraphs needed
    unsigned short e_maxalloc;   // Maximum extra paragraphs needed
    unsigned short e_ss;         // Initial (relative) SS value
    unsigned short e_sp;         // Initial SP value
    unsigned short e_csum;       // Checksum
    unsigned short e_ip;         // Initial IP value
    unsigned short e_cs;         // Initial (relative) CS value
    unsigned short e_lfarlc;     // File address of relocation table
    unsigned short e_ovno;       // Overlay number
    unsigned short e_res[4];     // Reserved words
    unsigned short e_oemid;      // OEM identifier (for e_oeminfo)
    unsigned short e_oeminfo;    // OEM information; e_oemid specific
    unsigned short e_res2[10];   // Reserved words
    long e_lfanew;               // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

// NT 頭部結構 (簡化版)
typedef struct {
    unsigned long Signature;
    unsigned short Machine;
    unsigned short NumberOfSections;
    unsigned long TimeDateStamp;
    unsigned long PointerToSymbolTable;
    unsigned long NumberOfSymbols;
    unsigned short SizeOfOptionalHeader;
    unsigned short Characteristics;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

// PE 區段頭部結構
typedef struct {
    char Name[8];
    unsigned long VirtualSize;
    unsigned long VirtualAddress;
    unsigned long SizeOfRawData;
    unsigned long PointerToRawData;
    unsigned long PointerToRelocations;
    unsigned long PointerToLinenumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLinenumbers;
    unsigned long Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

int ntcore_fd = -1;

int init_ntcore_device() {
    ntcore_fd = open(NT_DEVICE, O_RDWR);
    if (ntcore_fd < 0) {
        perror("Failed to open NT Core device");
        return -1;
    }
    return 0;
}

void cleanup_ntcore_device() {
    if (ntcore_fd >= 0) {
        close(ntcore_fd);
    }
}

// 模擬 PE Loader 功能
int load_pe_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open PE file");
        return -1;
    }

    IMAGE_DOS_HEADER dos_header;
    if (fread(&dos_header, sizeof(dos_header), 1, file) != 1) {
        perror("Failed to read DOS header");
        fclose(file);
        return -1;
    }

    if (dos_header.e_magic != 0x5A4D) { // "MZ"
        fprintf(stderr, "Not a valid PE file (DOS header)\n");
        fclose(file);
        return -1;
    }

    printf("PE file loaded: %s\n", filename);
    printf("DOS Header Magic: 0x%04X\n", dos_header.e_magic);
    printf("NT Header offset: 0x%08lX\n", dos_header.e_lfanew);

    // TODO: 完成 PE 檔案解析邏輯
    fclose(file);
    return 0;
}

// 執行 NT 系統呼叫的函數
int nt_create_process(const char *filename) {
    if (ntcore_fd < 0) return -1;

    struct nt_process_info proc_info;
    strncpy(proc_info.path, filename, sizeof(proc_info.path) - 1);
    proc_info.path[sizeof(proc_info.path) - 1] = '\0';

    return ioctl(ntcore_fd, NT_CREATE_PROCESS, &proc_info);
}

int nt_virtual_alloc(size_t size, unsigned long protect, unsigned long type) {
    if (ntcore_fd < 0) return -1;

    struct nt_mem_info mem_info;
    mem_info.addr = NULL;
    mem_info.size = size;
    mem_info.protect = protect;
    mem_info.type = type;

    return ioctl(ntcore_fd, NT_VIRTUAL_ALLOC, &mem_info);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pe_file>\n", argv[0]);
        return 1;
    }

    printf("NTCLKS PE Loader (ntuserd) starting...\n");

    if (init_ntcore_device() < 0) {
        fprintf(stderr, "Failed to initialize NT Core device\n");
        return 1;
    }

    if (load_pe_file(argv[1]) < 0) {
        fprintf(stderr, "Failed to load PE file: %s\n", argv[1]);
        cleanup_ntcore_device();
        return 1;
    }

    // TODO: 根據 PE 檔案資訊建立 NT 進程
    printf("PE file loaded, preparing to execute...\n");

    cleanup_ntcore_device();
    printf("NTCLKS PE Loader finished\n");
    return 0;
}