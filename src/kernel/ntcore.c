#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/version.h>

#define DEVICE_NAME "ntcore"
#define CLASS_NAME "nt"

// NT 物件類型定義
typedef enum _NT_OBJECT_TYPE {
    NT_TYPE_UNKNOWN = 0,
    NT_TYPE_PROCESS,
    NT_TYPE_THREAD,
    NT_TYPE_SECTION,
    NT_TYPE_EVENT,
    NT_TYPE_MUTANT,
    NT_TYPE_SEMAPHORE,
    NT_TYPE_TIMER,
    NT_TYPE_FILE,
    NT_TYPE_MEMORY,      // 用於記憶體管理物件
} NT_OBJECT_TYPE;

// NT 系統調用命令
#define NT_SYSCALL_BASE 0x1000
#define NT_VIRTUAL_ALLOC  _IOWR(NT_SYSCALL_BASE, 3, struct nt_mem_info)
#define NT_VIRTUAL_FREE   _IOWR(NT_SYSCALL_BASE, 4, struct nt_mem_info)
#define NT_VIRTUAL_PROTECT _IOWR(NT_SYSCALL_BASE, 5, struct nt_protect_info)
#define NT_CREATE_OBJECT  _IOWR(NT_SYSCALL_BASE, 6, struct nt_object_create_info)
#define NT_CLOSE_OBJECT   _IOWR(NT_SYSCALL_BASE, 7, struct nt_object_close_info)

// 物件創建資訊結構
struct nt_object_create_info {
    NT_OBJECT_TYPE type;
    uint64_t initial_params;
    uint64_t handle;  // 輸出：創建的物件句柄
};

// 物件關閉資訊結構
struct nt_object_close_info {
    uint64_t handle;
};

// NT 記憶體保護標誌 (使用不同的定義避免與內核衝突)
#define NTCLKS_PAGE_NOACCESS          0x01
#define NTCLKS_PAGE_READONLY          0x02
#define NTCLKS_PAGE_READWRITE         0x04
#define NTCLKS_PAGE_WRITECOPY         0x08
#define NTCLKS_PAGE_EXECUTE           0x10
#define NTCLKS_PAGE_EXECUTE_READ      0x20
#define NTCLKS_PAGE_EXECUTE_READWRITE 0x40
#define NTCLKS_PAGE_EXECUTE_WRITECOPY 0x80
#define NTCLKS_PAGE_GUARD             0x100
#define NTCLKS_PAGE_NOCACHE           0x200
#define NTCLKS_PAGE_WRITECOMBINE      0x400

// NT 記憶體分配類型
#define MEM_COMMIT    0x1000
#define MEM_RESERVE   0x2000
#define MEM_DECOMMIT  0x4000
#define MEM_RELEASE   0x8000
#define MEM_RESET     0x80000
#define MEM_TOP_DOWN  0x100000
#define MEM_PHYSICAL  0x400000
#define MEM_RESET_UNDO 0x1000000

// NT 資料結構定義
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

// NT 物件表結構
struct nt_object_entry {
    uint64_t handle;                         // NT 句柄
    NT_OBJECT_TYPE type;                     // 物件類型 (使用前面定義的類型)
    union {
        struct task_struct *linux_task;      // 進程/線程物件
        struct vm_area_struct *vma;          // 記憶體物件
        struct file *linux_file;             // 檔案物件
        void *generic_ptr;                   // 通用指針
    } linux_obj;
    uint32_t reference_count;                // 引用計數
    struct hlist_node hash_node;             // 哈希鏈表節點
    struct list_head list;                   // 用於全局物件列表
};

// 對象管理相關全局變量
#define NT_OBJECT_HASH_BITS 8
#define NT_OBJECT_HASH_SIZE (1 << NT_OBJECT_HASH_BITS)
#define NT_OBJECT_HASH_MASK (NT_OBJECT_HASH_SIZE - 1)

static DEFINE_SPINLOCK(object_table_lock);
static struct hlist_head nt_object_table[NT_OBJECT_HASH_SIZE];
static LIST_HEAD(nt_global_objects);         // 全局物件列表
static atomic64_t nt_handle_counter = ATOMIC64_INIT(0x100);  // 句柄計數器，從 0x100 開始

// NT 記憶體區塊追蹤結構
struct nt_mem_block {
    uint64_t base_addr;
    uint64_t size;
    uint32_t protect;
    uint32_t type;
    struct list_head list;
};

// 全局變量
static int major_number;
static struct class* ntclass = NULL;
static struct device* ntdevice = NULL;
static DEFINE_SPINLOCK(mem_list_lock);
static LIST_HEAD(nt_mem_list);  // 追蹤分配的記憶體區塊

// 對象管理系統初始化函數
static int __init nt_object_system_init(void)
{
    int i;
    
    // 初始化哈希表
    for (i = 0; i < NT_OBJECT_HASH_SIZE; i++) {
        INIT_HLIST_HEAD(&nt_object_table[i]);
    }
    
    // 初始化全局物件列表
    INIT_LIST_HEAD(&nt_global_objects);
    
    printk(KERN_INFO "NTCLKS: Object system initialized\n");
    return 0;
}

// 計算物件句柄的哈希值
static inline int nt_handle_hash(uint64_t handle)
{
    return (handle & NT_OBJECT_HASH_MASK);
}

// 在物件表中添加物件
static int nt_add_object(struct nt_object_entry *obj)
{
    int hash_bucket;
    
    if (!obj) {
        return -EINVAL;
    }
    
    spin_lock(&object_table_lock);
    
    // 分配句柄
    obj->handle = atomic64_inc_return(&nt_handle_counter);
    
    // 添加到哈希表
    hash_bucket = nt_handle_hash(obj->handle);
    hlist_add_head(&obj->hash_node, &nt_object_table[hash_bucket]);
    
    // 添加到全局列表
    list_add(&obj->list, &nt_global_objects);
    
    spin_unlock(&object_table_lock);
    
    return 0;
}

// 從物件表中移除物件
static int nt_remove_object(uint64_t handle)
{
    int hash_bucket;
    struct nt_object_entry *obj;
    
    hash_bucket = nt_handle_hash(handle);
    
    spin_lock(&object_table_lock);
    
    hlist_for_each_entry(obj, &nt_object_table[hash_bucket], hash_node) {
        if (obj->handle == handle) {
            hlist_del(&obj->hash_node);
            list_del(&obj->list);
            spin_unlock(&object_table_lock);
            
            // 釋放物件記憶體
            kfree(obj);
            return 0;
        }
    }
    
    spin_unlock(&object_table_lock);
    return -ENOENT;
}

// 將 NT 記憶體保護標誌轉換為 Linux 等效值
static inline pgprot_t nt_prot_to_linux_prot(uint32_t nt_protect) {
    pgprot_t prot;
    
    switch(nt_protect & 0xFF) {  // 低 8 位是保護類型
        case NTCLKS_PAGE_READONLY:
            prot = __pgprot(pgprot_val(PAGE_KERNEL) & ~_PAGE_RW);
            break;
        case NTCLKS_PAGE_READWRITE:
            prot = PAGE_KERNEL;
            break;
        case NTCLKS_PAGE_EXECUTE:
            prot = __pgprot(pgprot_val(PAGE_KERNEL_EXEC));
            break;
        case NTCLKS_PAGE_EXECUTE_READ:
            prot = __pgprot((pgprot_val(PAGE_KERNEL_EXEC) & ~_PAGE_RW));
            break;
        case NTCLKS_PAGE_EXECUTE_READWRITE:
            prot = PAGE_KERNEL_EXEC;
            break;
        case NTCLKS_PAGE_WRITECOPY:
            prot = PAGE_COPY;
            break;
        case NTCLKS_PAGE_EXECUTE_WRITECOPY:
            prot = __pgprot(pgprot_val(PAGE_COPY_EXEC));
            break;
        case NTCLKS_PAGE_NOACCESS:
        default:
            prot = __pgprot(0);
            break;
    }
    
    return prot;
}

// NT 記憶體分配實現
static long nt_virtual_alloc(struct nt_mem_info *info) {
    void *addr = NULL;
    struct nt_mem_block *mem_block;
    
    printk(KERN_INFO "NTCLKS: VirtualAlloc - addr: 0x%llx, size: 0x%llx, type: 0x%x, protect: 0x%x\n", 
           info->addr, info->size, info->type, info->protect);
    
    if (info->size == 0) {
        return -EINVAL;
    }
    
    // 檢查是否為釋放操作
    if (info->type & MEM_RELEASE) {
        // 如果是釋放操作，地址必須匹配已分配的區塊
        spin_lock(&mem_list_lock);
        list_for_each_entry(mem_block, &nt_mem_list, list) {
            if (mem_block->base_addr == info->addr) {
                vfree((void*)(unsigned long)mem_block->base_addr);
                list_del(&mem_block->list);
                kfree(mem_block);
                spin_unlock(&mem_list_lock);
                return 0; // 成功
            }
        }
        spin_unlock(&mem_list_lock);
        return -EINVAL; // 沒有找到要釋放的區塊
    }
    
    // 進行記憶體分配 - 預留或提交操作
    // 在這個簡化的實現中，我們同時處理預留和提交
    if ((info->type & MEM_RESERVE) || (info->type & MEM_COMMIT)) {
        // 指定地址的分配目前不支持，只支持任意地址分配
        if (info->addr != 0) {
            // 尋找特定地址的預留區塊
            spin_lock(&mem_list_lock);
            list_for_each_entry(mem_block, &nt_mem_list, list) {
                if (mem_block->base_addr == info->addr) {
                    // 更新現有預留區塊的屬性
                    mem_block->size = info->size;
                    mem_block->protect = info->protect;
                    mem_block->type |= info->type; // 添加新的分配類型
                    info->result_addr = mem_block->base_addr;
                    spin_unlock(&mem_list_lock);
                    return 0; // 成功
                }
            }
            spin_unlock(&mem_list_lock);
            return -EINVAL; // 沒有找到指定地址的預留區塊
        }
        
        // 在任意地址分配
        addr = vmalloc(info->size);
        if (!addr) {
            return -ENOMEM;
        }
        
        // 記錄分配的區塊
        mem_block = kmalloc(sizeof(struct nt_mem_block), GFP_KERNEL);
        if (!mem_block) {
            vfree(addr);
            return -ENOMEM;
        }
        
        mem_block->base_addr = (uint64_t)(unsigned long)addr;
        mem_block->size = info->size;
        mem_block->protect = info->protect;
        mem_block->type = info->type;
        
        spin_lock(&mem_list_lock);
        list_add(&mem_block->list, &nt_mem_list);
        spin_unlock(&mem_list_lock);
        
        info->result_addr = mem_block->base_addr;
    }
    
    return 0;
}

// NT 記憶體釋放實現
static long nt_virtual_free(struct nt_mem_info *info) {
    struct nt_mem_block *mem_block, *tmp;
    
    printk(KERN_INFO "NTCLKS: VirtualFree - addr: 0x%llx, size: 0x%llx, type: 0x%x\n", 
           info->addr, info->size, info->type);
    
    if (info->addr == 0) {
        return -EINVAL;
    }
    
    spin_lock(&mem_list_lock);
    list_for_each_entry_safe(mem_block, tmp, &nt_mem_list, list) {
        if (mem_block->base_addr == info->addr) {
            if (info->type & MEM_RELEASE) {
                // 釋放整個預留區塊
                if (info->size != 0) {
                    // Windows API 要求 MEM_RELEASE 時 size 必須為 0
                    spin_unlock(&mem_list_lock);
                    return -EINVAL;
                }
                
                vfree((void*)(unsigned long)mem_block->base_addr);
                list_del(&mem_block->list);
                kfree(mem_block);
                spin_unlock(&mem_list_lock);
                return 0; // 成功
            } else if (info->type & MEM_DECOMMIT) {
                // 取消提交 - 在 Linux 中沒有直接等效方式，但可以嘗試改變頁面訪問權限
                // 標記為取消提交狀態
                mem_block->type &= ~MEM_COMMIT;
                spin_unlock(&mem_list_lock);
                return 0; // 成功
            }
        }
    }
    spin_unlock(&mem_list_lock);
    
    return -EINVAL; // 沒有找到要釋放的區塊
}

// NT 記憶體保護變更實現
static long nt_virtual_protect(struct nt_protect_info *info) {
    struct nt_mem_block *mem_block;
    
    printk(KERN_INFO "NTCLKS: VirtualProtect - addr: 0x%llx, size: 0x%llx, new_protect: 0x%x\n", 
           info->addr, info->size, info->new_protect);
    
    if (info->addr == 0 || info->size == 0) {
        return -EINVAL;
    }
    
    // 在 Linux 中改變現有記憶體區域的保護需要特殊處理
    // 我們更新內部追蹤表中的保護值
    spin_lock(&mem_list_lock);
    list_for_each_entry(mem_block, &nt_mem_list, list) {
        if (info->addr >= mem_block->base_addr && 
            info->addr < mem_block->base_addr + mem_block->size) {
            // 找到相應的記憶體區塊，保存舊保護值
            info->old_protect = mem_block->protect;
            mem_block->protect = info->new_protect;
            
            // 在 Linux 中改變頁面保護通常需要重新映射
            // 這是一個簡化的實現，實際實現可能需要更複雜的頁面操作
            spin_unlock(&mem_list_lock);
            return 0; // 成功
        }
    }
    spin_unlock(&mem_list_lock);
    
    return -EINVAL; // 沒有找到相應的記憶體區塊
}

// NT 物件創建實現
static long nt_create_object(struct nt_object_create_info *info) {
    struct nt_object_entry *obj;
    int ret;
    
    printk(KERN_INFO "NTCLKS: CreateObject - type: %d\n", info->type);
    
    // 分配物件結構
    obj = kzalloc(sizeof(struct nt_object_entry), GFP_KERNEL);
    if (!obj) {
        return -ENOMEM;
    }
    
    obj->type = info->type;
    obj->reference_count = 1;
    // linux_obj 會根據物件類型進行初始化
    
    // 添加到物件表
    ret = nt_add_object(obj);
    if (ret) {
        kfree(obj);
        return ret;
    }
    
    // 返回創建的句柄
    info->handle = obj->handle;
    
    printk(KERN_INFO "NTCLKS: Object created with handle: 0x%llx\n", info->handle);
    
    return 0;
}

// NT 物件關閉實現
static long nt_close_object(struct nt_object_close_info *info) {
    printk(KERN_INFO "NTCLKS: CloseObject - handle: 0x%llx\n", info->handle);
    
    // 從物件表中移除物件
    return nt_remove_object(info->handle);
}

static long ntcore_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long result = 0;
    void __user *argp = (void __user *)arg;
    struct nt_mem_info mem_info;
    struct nt_protect_info protect_info;
    
    // 檢查命令是否為我們定義的 NT 系統調用之一
    if (_IOC_TYPE(cmd) != _IOC_TYPE(NT_VIRTUAL_ALLOC) &&
        _IOC_TYPE(cmd) != _IOC_TYPE(NT_VIRTUAL_FREE) &&
        _IOC_TYPE(cmd) != _IOC_TYPE(NT_VIRTUAL_PROTECT)) {
        return -ENOTTY;
    }
    
    switch (cmd) {
        case NT_VIRTUAL_ALLOC:
            if (copy_from_user(&mem_info, argp, sizeof(mem_info))) {
                return -EFAULT;
            }
            result = nt_virtual_alloc(&mem_info);
            if (result == 0) {
                // 如果成功，複製更新後的結果回用戶空間
                if (copy_to_user(argp, &mem_info, sizeof(mem_info))) {
                    return -EFAULT;
                }
            }
            break;
            
        case NT_VIRTUAL_FREE:
            if (copy_from_user(&mem_info, argp, sizeof(mem_info))) {
                return -EFAULT;
            }
            result = nt_virtual_free(&mem_info);
            break;
            
        case NT_VIRTUAL_PROTECT:
            if (copy_from_user(&protect_info, argp, sizeof(protect_info))) {
                return -EFAULT;
            }
            result = nt_virtual_protect(&protect_info);
            if (result == 0) {
                // 如果成功，複製可能更新的舊保護值回用戶空間
                if (copy_to_user(argp, &protect_info, sizeof(protect_info))) {
                    return -EFAULT;
                }
            }
            break;
            
        case NT_CREATE_OBJECT:
            {
                struct nt_object_create_info obj_info;
                if (copy_from_user(&obj_info, argp, sizeof(obj_info))) {
                    return -EFAULT;
                }
                result = nt_create_object(&obj_info);
                if (result == 0) {
                    // 如果成功，複製創建的句柄回用戶空間
                    if (copy_to_user(argp, &obj_info, sizeof(obj_info))) {
                        return -EFAULT;
                    }
                }
            }
            break;
            
        case NT_CLOSE_OBJECT:
            {
                struct nt_object_close_info obj_info;
                if (copy_from_user(&obj_info, argp, sizeof(obj_info))) {
                    return -EFAULT;
                }
                result = nt_close_object(&obj_info);
            }
            break;
            
        default:
            printk(KERN_WARNING "NTCLKS: Unknown ioctl command: %u\n", cmd);
            return -ENOTTY;
    }
    
    return result;
}

static struct file_operations fops = {
    .unlocked_ioctl = ntcore_ioctl,
    .owner = THIS_MODULE,
};

static int __init ntcore_init(void)
{
    int ret;
    
    printk(KERN_INFO "NTCLKS: Initializing NT Core module\n");

    // 初始化物件系統
    ret = nt_object_system_init();
    if (ret) {
        printk(KERN_ALERT "NTCLKS: Failed to initialize object system\n");
        return ret;
    }

    // 註冊字元裝置
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "NTCLKS: Failed to register major number\n");
        return major_number;
    }

    // 建立裝置類別
    ntclass = class_create(CLASS_NAME);
    if (IS_ERR(ntclass)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "NTCLKS: Failed to register device class\n");
        return PTR_ERR(ntclass);
    }

    // 建立裝置節點
    ntdevice = device_create(ntclass, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(ntdevice)) {
        class_destroy(ntclass);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "NTCLKS: Failed to create device\n");
        return PTR_ERR(ntdevice);
    }

    printk(KERN_INFO "NTCLKS: Device created successfully\n");
    return 0;
}

static void __exit ntcore_exit(void)
{
    struct nt_object_entry *obj, *tmp;
    
    // 清理所有剩餘的物件
    spin_lock(&object_table_lock);
    list_for_each_entry_safe(obj, tmp, &nt_global_objects, list) {
        list_del(&obj->list);
        hlist_del(&obj->hash_node);
        kfree(obj);
    }
    spin_unlock(&object_table_lock);
    
    device_destroy(ntclass, MKDEV(major_number, 0));
    class_unregister(ntclass);
    class_destroy(ntclass);
    unregister_chrdev(major_number, DEVICE_NAME);
    printk(KERN_INFO "NTCLKS: NT Core module unloaded\n");
}

module_init(ntcore_init);
module_exit(ntcore_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NTCLKS Team");
MODULE_DESCRIPTION("NT-Compatible Linux Kernel Subsystem");
MODULE_VERSION("0.1");