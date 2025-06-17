//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32; 

    bpf_printk("[%d] unlinkat(%s)\n", pid, name->name);

    return 0;
}

SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit,  int ret)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32; 

    bpf_printk("[%d] unlinkat() returned %d\n", pid, ret);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";