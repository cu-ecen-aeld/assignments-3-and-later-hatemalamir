/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Hatem Alamir");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence) {
    struct aesd_dev *dev = filp->private_data;
    loff_t newpos;

    switch(whence) {
        case 0: /*SEEK_SET*/
            newpos = off;
            break;
        case 1: /*SEEK_CUR*/
            newpos = filp->f_pos + off;
            break;
        case 2: /*SEEK_END*/
            newpos = dev->size + off;
            break;
        default:
            return -EINVAL;
    }

    if(newpos < 0)
        return -EINVAL;
    filp->f_pos = newpos;
    return newpos;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    if(mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_read: interrupted while waiting for mutex. Restarting.");
        return -ERESTARTSYS;
    }
    size_t byte_idx;
    struct aesd_buffer_entry *buf_entry = aesd_circular_buffer_find_entry_offset_for_fpos(dev->buff, *f_pos, &byte_idx);
    if(buf_entry == NULL) {
        PDEBUG("aesd_read: failed to read from offset %lld. Out of range!", *f_pos);
        goto out;
    }
    if(count > buf_entry->size)
        count = buf_entry->size;
    if(copy_to_user(buf, buf_entry->buffptr, count)) {
        PDEBUG("aesd_read: failed to copy to user space!");
        retval = -EFAULT;
        goto out;
    }
    PDEBUG("aesd_read: read %zu bytes from offset %lld", count, *f_pos);
    *f_pos += count;
    retval = count;
out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    // initialization
    struct aesd_dev *dev = filp->private_data;
    if(mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_write: interrupted while waiting for mutex. Restarting.");
        return -ERESTARTSYS;
    }
    ssize_t retval = -ENOMEM;
    // receiving data from user space
    char *recv_buff = kmalloc(count, GFP_KERNEL);
    if(!recv_buff) {
        PDEBUG("aesd_write: failed to allocate %zu bytes for recv_buf.", count);
        goto out;
    }
    if(copy_from_user(recv_buff, buf, count)) {
        PDEBUG("aesd_write: failed to copy %zu bytes from user space.", count);
        retval = -EFAULT;
        goto clean;
    }
    //looking up commands in received data
    size_t out_idx = 0;
    for(size_t idx = 0; idx < count; idx++)
        if(recv_buff[idx] ==  '\n') {
            size_t total_size = idx - out_idx + 1;
            struct write_entry *cur = dev->write_buff;
            while(cur != NULL) {
                total_size += cur->size;
                cur = cur->next;
            }
            struct aesd_buffer_entry entry;
            entry.buffptr = kmalloc(total_size, GFP_KERNEL);
            if(!entry.buffptr) {
                PDEBUG("aesd_write: failed to allocate %zu bytes for command.", total_size);
                goto clean;
            }
            size_t copied_bytes = 0;
            cur = dev->write_buff;
            while(dev->write_buff != NULL) {
                memcpy(entry.buffptr + copied_bytes, dev->write_buff->data, dev->write_buff->size);
                copied_bytes += dev->write_buff->size;
                cur = dev->write_buff; 
                dev->write_buff = dev->write_buff->next;
                kfree(cur->data);
                kfree(cur);
            }
            memcpy(entry.buffptr + copied_bytes, recv_buff + out_idx, idx - out_idx + 1);
            entry.size = total_size;
            struct aesd_buffer_entry ret = aesd_circular_buffer_add_entry(dev->buff, &entry);
            kfree(ret.buffptr);
            out_idx = idx + 1;
        }
    // cache incomplete commands
    if(out_idx < count) {
        struct write_entry *wntry = kmalloc(sizeof(struct write_entry), GFP_KERNEL);
        if(!wntry) {
            PDEBUG("aesd_write: failed to allocate write_entry.");
            goto clean;
        }
        size_t wsize = count - out_idx;
        wntry->data = kmalloc(wsize, GFP_KERNEL);
        if(!wntry->data) {
            PDEBUG("aesd_write: failed to allocate %zu bytes for write_entry.", wsize);
            kfree(wntry);
            goto clean;
        }
        memcpy(wntry->data, recv_buff + out_idx, wsize);
        wntry->size = wsize;
        wntry->next = NULL;
        if(dev->write_buff == NULL)
            dev->write_buff = wntry;
        else {
            struct write_entry *last = dev->write_buff;
            while(last->next != NULL)
                last = last->next;
            last->next = wntry;
        }
    }

    PDEBUG("aesd_write: wrote %zu bytes at offset %lld", count, *f_pos);
    *f_pos += count;
    retval = count;
clean:
    kfree(recv_buff);
out:
    mutex_unlock(&dev->lock);
    return retval;
}

long seek_ctl(struct file *filp, const void __user *user_buff) {
    struct aesd_seekto seek_buff;
    memset(&seek_buff,0,sizeof(struct aesd_seekto));
    if(copy_from_user(&seek_buff, user_buff, sizeof(struct aesd_seekto))) {
        PDEBUG("aesd_ioctl: failed to copy aesd_seekto from user space.");
        return -EFAULT;
    }

    //validate parameters
    if(aesd_device.buff.in_offs == aesd_device.buff.out_offs) {
        PDEBUG("seek_ctl: device buffer is empty.");
        return -EINVAL;
    }
    if(seek_buff.write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED || (!aesd_device.buff.full && seek_buff.write_cmd > aesd_device.buff.out_offs)) {
        PDEBUG("seek_ctl: out of range write_cmd %" PRIu32);
        return -EINVAL;
    }
    uint32_t entry_idx = (aesd_device.buff.out_offs + seek_buff.write_cmd) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED ? aesd_device.buff.full : seek_buff.write_cmd;
    if(seek_buff.write_cmd_offset >= aesd_device.buff->entry[entry_idx].size) {
        PDEBUG("seek_ctl: out of range write_cmd_offset %" PRIu32);
        return -EINVAL;
    }

    uint32_t seek_off = 0;
    for(uint32_t idx = aesd_device.buff.out_offs; idx < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; idx = (idx + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
        if(idx == entry_idx) {
            seek_off += seek_buff.write_cmd_offset;
            break;
        }
        seek_off += aesd_device.buff->entry[idx].size;
    }
    aesd_llseek(filp, seek_off, SEEK_SET);

    return 0;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    if(_IOC_TYPE(cmd) != AESD_IOC_MAGIC)
        return -ENOTTY;
    if(_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
        return -ENOTTY;

    switch(cmd) {
        case AESDCHAR_IOCSEEKTO:
            return seek_ctl(filp, arg);
        default:
            return -ENOTTY;
    }

    return 0;
}

struct file_operations aesd_fops = {
    .owner =          THIS_MODULE,
    .llseek =         aesd_llseek,
    .read =           aesd_read,
    .write =          aesd_write,
    .unlocked_ioctl = aesd_ioctl;
    .open =           aesd_open,
    .release =        aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    aesd_major = MAJOR(dev);
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    mutex_init(&aesd_device.lock);
    aesd_device.buff = kmalloc(sizeof(struct aesd_circular_buffer), GFP_KERNEL);
    if(!aesd_device.buff) {
        printk(KERN_WARNING "Can't allocate circular buffer\n");
        unregister_chrdev_region(dev, 1);
        return -EFAULT;
    }
    for(size_t eidx = 0; eidx < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; eidx++)
        aesd_device.buff->entry[eidx].buffptr = NULL;
    aesd_device.buff->in_offs = 0;
    aesd_device.buff->out_offs = 0;
    aesd_device.buff->full = false;

    result = aesd_setup_cdev(&aesd_device);
    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    struct write_entry *wedel;
    while(aesd_device.write_buff != NULL) {
        kfree(aesd_device.write_buff->data);
        wedel = aesd_device.write_buff;
        aesd_device.write_buff = aesd_device.write_buff->next;
        kfree(wedel);
    }
    for(size_t eidx = 0; eidx < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; eidx++)
        if(aesd_device.buff->entry[eidx].buffptr != NULL)
            kfree(aesd_device.buff->entry[eidx].buffptr);
    kfree(aesd_device.buff);

    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
