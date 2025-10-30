#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>

#define DEVICE_NAME "ntcore"
#define CLASS_NAME "nt"

static int major_number;
static struct class* ntclass = NULL;
static struct device* ntdevice = NULL;

static long ntcore_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    // TODO: 實作 NT 系統呼叫的 ioctl 處理邏輯
    printk(KERN_INFO "NTCLKS: ioctl command received %u\n", cmd);
    return 0;
}

static struct file_operations fops = {
    .unlocked_ioctl = ntcore_ioctl,o
};

static int __init ntcore_init(void)
{
    printk(KERN_INFO "NTCLKS: Initializing NT Core module\n");

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