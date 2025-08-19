#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <taskext.h>
#include "file.h"
#include "data_parse.h"

KPM_NAME("io_redirect");
KPM_VERSION("5.2.0");
KPM_AUTHOR("yuuki");
KPM_DESCRIPTION("Redirect target file to customized path");



typedef struct file *(*do_filp_open_func_t)(int dfd, struct filename *pathname, const struct open_flags *op);
char *(*d_path)(const struct path *path, char *buf, int buflen) = NULL;
void (*fput)(struct file *file) = NULL;
void *(*kf_vmalloc)(unsigned long size) = NULL;
void (*kf_vfree)(const void *addr) = NULL;


static do_filp_open_func_t original_do_filp_open = NULL;
static do_filp_open_func_t backup_do_filp_open = NULL;
static hook_err_t hook_err = HOOK_NOT_HOOK;
static char source_paths[MAX_LINES][PATH_MAX];
static char redirect_paths[MAX_LINES][PATH_MAX];
static int line_count = 0;

// 替换 do_filp_open 函数的声明
static struct file *replace_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);


// 设置任务的SELinux权限允许标志
// task: 指向任务结构体的指针
// val: 要设置的值（0表示不允许，1表示允许）
static inline void set_priv_selinx_allow(struct task_struct* task, int val) {
    // 获取任务的扩展结构体
    struct task_ext* ext = get_task_ext(task);
    
    // 检查扩展结构体是否有效（likely表示该条件很可能为真）
    if (likely(task_ext_valid(ext))) {
        // 设置SELinux权限允许标志
        ext->priv_selinux_allow = val;
        
        // 数据同步屏障指令(ARM架构)
        // 确保之前的内存操作都完成后再执行后续操作
        dsb(ish);
    }
}

// 替换系统调用 do_filp_open 的函数，用于文件路径重定向
// dfd: 文件描述符
// pathname: 指向文件名结构体的指针
// op: 指向打开标志结构体的指针
// 返回: 打开的文件结构体指针
static struct file *replace_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op) {
    // 调用备份的原始 do_filp_open 函数打开文件
    struct file *filp = backup_do_filp_open(dfd, pathname, op);
    
    // 检查文件是否成功打开（likely 表示该条件很可能为真）
    if (likely(!IS_ERR(filp))) {
        char buf[PATH_MAX];                  // 存储文件路径的缓冲区
        memset(&buf, 0, PATH_MAX);           // 清空缓冲区
        // 获取文件的绝对路径
        char *currPath = d_path(&filp->f_path, buf, PATH_MAX);

        // 遍历所有配置的路径对
        for (int i = 0; i < line_count; i++){
            // 检查当前路径是否匹配源路径
            if (strncmp(currPath, source_paths[i], strlen(source_paths[i])) == 0) {
                pr_info("[yuuki] Interception path %s successful, redirect to %s\n", source_paths[i], redirect_paths[i]);
                
                // 释放当前打开的文件
                fput(filp);

                // 为新路径分配内存
                struct filename *new_pathname = kf_vmalloc(sizeof(struct filename));
                if (!new_pathname) {
                    return ERR_PTR(-ENOMEM);  // 内存分配失败
                }
                new_pathname->name = redirect_paths[i];  // 设置重定向路径

                // 设置 SELinux 权限允许标志为 true，允许特权操作
                set_priv_selinx_allow(current, true);
                // 打开重定向路径的文件
                struct file *redirect_filp = backup_do_filp_open(dfd, new_pathname, op);
                // 恢复 SELinux 权限允许标志为 false
                set_priv_selinx_allow(current, false);

                // 释放新路径的内存
                kf_vfree(new_pathname);
                return redirect_filp;  // 返回重定向后的文件结构体
            }
        }
    }
    // 如果没有匹配的路径或打开失败，返回原始文件结构体
    return filp;
}
// hook do_filp_open 函数
static inline bool hook_do_filp_open() {
    if (original_do_filp_open) {
        hook_err = hook((void *)original_do_filp_open, (void *)replace_do_filp_open, (void **)&backup_do_filp_open);
        if (hook_err != HOOK_NO_ERR) {
            pr_info("[yuuki] hook do_filp_open, %llx, error: %d\n", original_do_filp_open, hook_err);
        } else {
            return true;
        }
    } else {
        hook_err = HOOK_BAD_ADDRESS;
        pr_err("[yuuki] no symbol: do_filp_open\n");
    }
    return false;
}

// hook模块安装函数
static inline bool installHook() {
    bool ret = false;

    if (hook_err != HOOK_NO_ERR) {
        if (hook_do_filp_open()) {
            pr_info("[yuuki] hook installed...\n");
            ret = true;
        } else {
            pr_err("[yuuki] hook installation failed...\n");
        }
    } else {
        pr_info("[yuuki] hook already installed, skipping...\n");
        ret = true;
    }

    return ret;
}
// hook模块卸载函数
static inline bool uninstallHook() {
    if (hook_err == HOOK_NO_ERR) {
        unhook((void *)original_do_filp_open);
        hook_err = HOOK_NOT_HOOK;
        pr_info("[yuuki] hook uninstalled...\n");
    } else {
        pr_info("[yuuki] Maybe it's not hooked, skipping...\n");
    }
    return true;
}
// 模块控制函数1
static inline bool control_internal(bool enable) {
    return enable ? installHook() : uninstallHook();
}
// 模块初始化函数
static long mod_init(const char *args, const char *event, void *__user reserved){
    pr_info("[yuuki] Initializing...\n");
    // 获取do_filp_open函数的地址
    original_do_filp_open = (do_filp_open_func_t)kallsyms_lookup_name("do_filp_open");
    if (!original_do_filp_open) {
        pr_info("[yuuki] kernel func: 'do_filp_open' does not exist!\n");
        goto exit;
    }

    long ret = 0;

    pr_info("[yuuki] Kernel Version: %x\n", kver);
    pr_info("[yuuki] Kernel Patch Version: %x\n", kpver);
    // 初始化内核函数指针: vmalloc
    kf_vmalloc = (typeof(kf_vmalloc))kallsyms_lookup_name("vmalloc");
    if (!kf_vmalloc) {
        pr_info("[yuuki] kernel func: 'vmalloc' does not exist!\n");
        goto exit;
    }   
    // 初始化内核函数指针: vfree
    kf_vfree = (typeof(kf_vfree))kallsyms_lookup_name("vfree");
    if (!kf_vfree) {
        pr_info("[yuuki] kernel func: 'vfree' does not exist!\n");
        goto exit;
    }
     // 初始化内核函数指针: d_path
    d_path = (typeof(d_path))kallsyms_lookup_name("d_path");
    if (!d_path) {
        pr_info("[yuuki] kernel func: 'd_path' does not exist!\n");
        goto exit;
    }
    // 初始化内核函数指针: fput
    fput = (typeof(fput))kallsyms_lookup_name("fput");
    if (!fput) {
        pr_info("[yuuki] kernel func: 'fput' does not exist!\n");
        goto exit;
    }

    exit:
    return ret;
}
// 模块控制函数0
static long mod_control0(const char *args, char *__user out_msg, int outlen) {
    pr_info("[yuuki] kpm hello control0, args: %s\n", args);

    parsePaths(args, source_paths, redirect_paths, &line_count);

    for (int i = 0; i < line_count; i++) {
        pr_info("[yuuki] source_path: %s redirect_path: %s\n", source_paths[i], redirect_paths[i]);
    }

    control_internal(true);

    return 0;
}
// 模块退出函数
static long mod_exit(void *__user reserved) {
    control_internal(false);
    pr_info("[yuuki] mod_exit, uninstalled hook.\n");
    return 0;
}

KPM_INIT(mod_init);
KPM_CTL0(mod_control0);
KPM_EXIT(mod_exit);