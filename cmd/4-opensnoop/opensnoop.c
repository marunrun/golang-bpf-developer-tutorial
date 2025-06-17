//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

const volatile int pid_target = 0;

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_syscalls_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    pid_t pid;
    pid = bpf_get_current_pid_tgid() >> 32;
    if (pid_target && pid != pid_target)
        return false;

    bpf_printk("Process ID: %d enter sys openat\n", pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";