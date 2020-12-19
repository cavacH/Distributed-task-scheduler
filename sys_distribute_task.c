#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <uapi/linux/limits.h>
#include <linux/string.h>
#include <linux/fs.h>

#define PROC_FIFO_NAME "DTS-fifo"

SYSCALL_DEFINE3(distribute_task, 
                const char __user *, exe_filepath,
                int, argc,
                const char __user * const __user *, argv) {
    char *path = NULL, **__argv = NULL, **kargv = NULL;
    int i;
    long len, err = 0, tot_len = 0;
    struct file *f = NULL;
    char fifo_path[NAME_MAX + 10], *cmd;

    len = strnlen_user(exe_filepath, PATH_MAX) + 1;
    path = (char *) kmalloc(len, GFP_KERNEL);
    tot_len += len - 1;
    if(strncpy_from_user(&path[0], exe_filepath, len - 1) < 0) {
        err = -EFAULT;
        goto ret;
    }
        
    //printk(KERN_INFO "File path: %s\n", path);
    //printk(KERN_INFO "Argc: %d\n", argc);
    
    __argv = (char **) kmalloc(argc * sizeof(char *), GFP_KERNEL);
    if(copy_from_user(__argv, argv, argc * sizeof(char *))) {
        err = -EFAULT;
        goto ret;
    }
    
    kargv = (char **) kmalloc(argc * sizeof(char *), GFP_KERNEL);
    for(i = 0; i < argc; i++) {
        len = strnlen_user(__argv[i], NAME_MAX) + 1;
        kargv[i] = (char *) kmalloc(len, GFP_KERNEL);
        tot_len += len;
        if(strncpy_from_user(&kargv[i][0], __argv[i], len - 1) < 0) {
            err = -EFAULT;
            goto ret;
        }
        //printk(KERN_INFO "Argv %d: %s\n", i, kargv[i]);
    }

    strcpy(fifo_path, "/proc/");
    strcat(fifo_path, PROC_FIFO_NAME);
    //printk(KERN_INFO "FIFO_PATH: %s\n", fifo_path);
    
    f = filp_open(fifo_path, O_WRONLY | O_APPEND, 0);
    if(IS_ERR(f)) {
        err = PTR_ERR(f);
        goto ret; 
    }
    cmd = (char *) kmalloc(tot_len + 1, GFP_KERNEL);
    strcpy(cmd, path);
    for(i = 0; i < argc; i++) {
        strcat(cmd, " ");
        strcat(cmd, kargv[i]);
    }

    if((len = kernel_write(f, cmd, strlen(cmd) + 1, NULL)) > 0) {
        //printk(KERN_INFO "Write to FIFO: %s\n", cmd);
    }
    filp_close(f, NULL);

ret:
    if(path)
        kfree(path);
    if(__argv)
        kfree(__argv);
    if(kargv) {
        for(i = 0; i < argc; i++)
            kfree(kargv[i]);
        kfree(kargv);
    }
    if(cmd)
        kfree(cmd);
    return err;
}

