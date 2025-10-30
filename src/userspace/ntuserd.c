#include <errno.h>
#include <stdint.h>
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

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE  0x00004550
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B

// PE 檔案結構定義
typedef struct __attribute__((packed)) {
    uint16_t e_magic;      // Magic number
    uint16_t e_cblp;       // Bytes on last page of file
    uint16_t e_cp;         // Pages in file
    uint16_t e_crlc;       // Relocations
    uint16_t e_cparhdr;    // Size of header in paragraphs
    uint16_t e_minalloc;   // Minimum extra paragraphs needed
    uint16_t e_maxalloc;   // Maximum extra paragraphs needed
    uint16_t e_ss;         // Initial (relative) SS value
    uint16_t e_sp;         // Initial SP value
    uint16_t e_csum;       // Checksum
    uint16_t e_ip;         // Initial IP value
    uint16_t e_cs;         // Initial (relative) CS value
    uint16_t e_lfarlc;     // File address of relocation table
    uint16_t e_ovno;       // Overlay number
    uint16_t e_res[4];     // Reserved words
    uint16_t e_oemid;      // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;    // OEM information; e_oemid specific
    uint16_t e_res2[10];   // Reserved words
    int32_t e_lfanew;      // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct __attribute__((packed)) {
    uint32_t VirtualAddress;
    uint32_t Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct __attribute__((packed)) {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct __attribute__((packed)) {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct __attribute__((packed)) {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct __attribute__((packed)) {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct {
    uint8_t *image_base;
    size_t image_size;
    uint64_t preferred_base;
    uint64_t entry_point_rva;
    int is_pe64;
} pe_image;

static void free_pe_image(pe_image *image) {
    if (!image) {
        return;
    }
    free(image->image_base);
    image->image_base = NULL;
    image->image_size = 0;
}

static int allocate_pe_image(pe_image *image, size_t size) {
    image->image_base = calloc(1, size);
    if (!image->image_base) {
        return -1;
    }
    image->image_size = size;
    return 0;
}

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

static void dump_section_info(const IMAGE_SECTION_HEADER *section) {
    char name[9];
    memset(name, 0, sizeof(name));
    memcpy(name, section->Name, sizeof(section->Name));

    printf("  Section %-8s | RVA 0x%08X | RawSize 0x%08X | Characteristics 0x%08X\n",
           name,
           section->VirtualAddress,
           section->SizeOfRawData,
           section->Characteristics);
}

static int copy_section_into_image(FILE *file, const IMAGE_SECTION_HEADER *section, pe_image *image) {
    size_t raw_size = section->SizeOfRawData;
    size_t virtual_size = section->VirtualSize ? section->VirtualSize : raw_size;
    size_t section_end = (size_t)section->VirtualAddress + virtual_size;

    if (section_end > image->image_size || section_end < section->VirtualAddress) {
        fprintf(stderr, "Section does not fit in allocated image: RVA=0x%X Size=0x%zX ImageSize=0x%zX\n",
                section->VirtualAddress,
                virtual_size,
                image->image_size);
        return -1;
    }

    if (raw_size == 0) {
        return 0;
    }

    if (fseek(file, section->PointerToRawData, SEEK_SET) != 0) {
        perror("Failed to seek to section data");
        return -1;
    }

    if (fread(image->image_base + section->VirtualAddress,
              raw_size,
              1,
              file) != 1) {
        perror("Failed to read section data");
        return -1;
    }

    return 0;
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

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "Not a valid PE file (DOS header)\n");
        fclose(file);
        return -1;
    }

    if (fseek(file, dos_header.e_lfanew, SEEK_SET) != 0) {
        perror("Failed to seek to NT headers");
        fclose(file);
        return -1;
    }

    uint32_t signature = 0;
    if (fread(&signature, sizeof(signature), 1, file) != 1) {
        perror("Failed to read NT signature");
        fclose(file);
        return -1;
    }

    if (signature != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "Not a valid PE file (NT signature mismatch)\n");
        fclose(file);
        return -1;
    }

    IMAGE_FILE_HEADER file_header;
    if (fread(&file_header, sizeof(file_header), 1, file) != 1) {
        perror("Failed to read file header");
        fclose(file);
        return -1;
    }

    printf("PE file loaded: %s\n", filename);
    printf("Machine: 0x%04X | Sections: %u | OptionalHeaderSize: %u bytes\n",
           file_header.Machine,
           file_header.NumberOfSections,
           file_header.SizeOfOptionalHeader);

    if (file_header.NumberOfSections == 0) {
        fprintf(stderr, "PE file does not contain any section\n");
        fclose(file);
        return -1;
    }

    uint8_t *optional_header_raw = malloc(file_header.SizeOfOptionalHeader);
    if (!optional_header_raw) {
        perror("Failed to allocate optional header buffer");
        fclose(file);
        return -1;
    }

    if (fread(optional_header_raw, file_header.SizeOfOptionalHeader, 1, file) != 1) {
        perror("Failed to read optional header");
        free(optional_header_raw);
        fclose(file);
        return -1;
    }

    pe_image image = {0};

    uint16_t optional_magic = *(uint16_t *)optional_header_raw;
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            fprintf(stderr, "Optional header too small for PE32 format\n");
            free(optional_header_raw);
            fclose(file);
            return -1;
        }

        IMAGE_OPTIONAL_HEADER32 *opt32 = (IMAGE_OPTIONAL_HEADER32 *)optional_header_raw;
        printf("PE32 Optional Header: EntryPoint RVA 0x%08X | ImageBase 0x%08X | SizeOfImage 0x%08X\n",
               opt32->AddressOfEntryPoint,
               opt32->ImageBase,
               opt32->SizeOfImage);
        image.preferred_base = opt32->ImageBase;
        image.entry_point_rva = opt32->AddressOfEntryPoint;
        image.is_pe64 = 0;

        if (allocate_pe_image(&image, opt32->SizeOfImage) != 0) {
            fprintf(stderr, "Failed to allocate memory for PE image of size 0x%X\n", opt32->SizeOfImage);
            free(optional_header_raw);
            fclose(file);
            return -1;
        }
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            fprintf(stderr, "Optional header too small for PE32+ format\n");
            free(optional_header_raw);
            fclose(file);
            return -1;
        }

        IMAGE_OPTIONAL_HEADER64 *opt64 = (IMAGE_OPTIONAL_HEADER64 *)optional_header_raw;
        printf("PE32+ Optional Header: EntryPoint RVA 0x%08X | ImageBase 0x%llX | SizeOfImage 0x%08X\n",
               opt64->AddressOfEntryPoint,
               (unsigned long long)opt64->ImageBase,
               opt64->SizeOfImage);
        image.preferred_base = opt64->ImageBase;
        image.entry_point_rva = opt64->AddressOfEntryPoint;
        image.is_pe64 = 1;

        if (allocate_pe_image(&image, opt64->SizeOfImage) != 0) {
            fprintf(stderr, "Failed to allocate memory for PE image of size 0x%X\n", opt64->SizeOfImage);
            free(optional_header_raw);
            fclose(file);
            return -1;
        }
    } else {
        fprintf(stderr, "Unsupported optional header magic: 0x%04X\n", optional_magic);
        free(optional_header_raw);
        fclose(file);
        return -1;
    }

    free(optional_header_raw);

    IMAGE_SECTION_HEADER *sections = calloc(file_header.NumberOfSections, sizeof(IMAGE_SECTION_HEADER));
    if (!sections) {
        perror("Failed to allocate section headers");
        free_pe_image(&image);
        fclose(file);
        return -1;
    }

    if (fread(sections, sizeof(IMAGE_SECTION_HEADER), file_header.NumberOfSections, file) != file_header.NumberOfSections) {
        perror("Failed to read section headers");
        free(sections);
        free_pe_image(&image);
        fclose(file);
        return -1;
    }

    printf("Sections:\n");
    for (uint16_t i = 0; i < file_header.NumberOfSections; ++i) {
        dump_section_info(&sections[i]);
        if (copy_section_into_image(file, &sections[i], &image) != 0) {
            fprintf(stderr, "Failed to load section %u\n", i);
            free(sections);
            free_pe_image(&image);
            fclose(file);
            return -1;
        }
    }

    uint64_t entry_point = image.preferred_base + image.entry_point_rva;
    printf("PE image mapped at 0x%llX (preferred base 0x%llX). Entry point: 0x%llX\n",
           (unsigned long long)(uintptr_t)image.image_base,
           (unsigned long long)image.preferred_base,
           (unsigned long long)entry_point);

    free(sections);
    free_pe_image(&image);
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