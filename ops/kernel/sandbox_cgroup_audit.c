// SPDX-License-Identifier: GPL-2.0
/*
 * Sandbox cgroup audit module.
 *
 * This module does not replace Linux cgroup v2 enforcement. It provides a
 * tiny kernel-space audit surface for the sandbox cgroup policy used by the
 * Docker Compose and ops/create_cgroups.sh configuration.
 */

#include <linux/cred.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/uidgid.h>

#define SANDBOX_PROC_NAME "sandbox_cgroup_audit"

static char *sandbox_cgroup = "/sys/fs/cgroup/msdss_sandbox";
static unsigned int memory_limit_mb = 256;
static unsigned int pids_limit = 64;
static unsigned int cpu_percent = 20;

module_param(sandbox_cgroup, charp, 0444);
MODULE_PARM_DESC(sandbox_cgroup, "Expected cgroup v2 path for the sandbox");

module_param(memory_limit_mb, uint, 0444);
MODULE_PARM_DESC(memory_limit_mb, "Expected sandbox memory.max value in MiB");

module_param(pids_limit, uint, 0444);
MODULE_PARM_DESC(pids_limit, "Expected sandbox pids.max value");

module_param(cpu_percent, uint, 0444);
MODULE_PARM_DESC(cpu_percent, "Expected sandbox CPU quota percentage");

static struct proc_dir_entry *sandbox_proc_entry;

static void sandbox_seq_timestamp(struct seq_file *m)
{
    struct timespec64 now;

    ktime_get_real_ts64(&now);
    seq_printf(m, "timestamp_ms=%lld.%03ld\n",
           (long long)now.tv_sec,
           now.tv_nsec / 1000000L);
}

static int sandbox_proc_show(struct seq_file *m, void *v)
{
    unsigned long cpu_quota;
    unsigned long cpu_period = 100000UL;

    cpu_quota = ((unsigned long)cpu_percent * cpu_period) / 100UL;

    seq_puts(m, "sandbox_kernel_audit=enabled\n");
    sandbox_seq_timestamp(m);
    seq_printf(m, "reader_pid=%d\n", task_pid_nr(current));
    seq_printf(m, "reader_comm=%s\n", current->comm);
    seq_printf(m, "reader_uid=%u\n",
           from_kuid(&init_user_ns, current_uid()));
    seq_printf(m, "sandbox_cgroup=%s\n", sandbox_cgroup);
    seq_printf(m, "expected_memory_max_bytes=%u\n",
           memory_limit_mb * 1024U * 1024U);
    seq_printf(m, "expected_pids_max=%u\n", pids_limit);
    seq_printf(m, "expected_cpu_max=%lu %lu\n", cpu_quota, cpu_period);
    seq_printf(m, "kernel_jiffies=%lu\n", jiffies);
    return 0;
}

static int sandbox_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, sandbox_proc_show, NULL);
}

static const struct proc_ops sandbox_proc_ops = {
    .proc_open = sandbox_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init sandbox_cgroup_audit_init(void)
{
    sandbox_proc_entry = proc_create(SANDBOX_PROC_NAME, 0444, NULL,
                       &sandbox_proc_ops);
    if (!sandbox_proc_entry)
        return -ENOMEM;
    pr_info("Sandbox cgroup audit module loaded: cgroup=%s memory=%uMiB pids=%u cpu=%u%%\n",
        sandbox_cgroup, memory_limit_mb, pids_limit, cpu_percent);
    return 0;
}

static void __exit sandbox_cgroup_audit_exit(void)
{
    proc_remove(sandbox_proc_entry);
    pr_info("Sandbox cgroup audit module unloaded\n");
}

module_init(sandbox_cgroup_audit_init);
module_exit(sandbox_cgroup_audit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sandbox");
MODULE_DESCRIPTION("Kernel-space procfs audit module for sandbox cgroup v2 policy");
MODULE_VERSION("1.0");
