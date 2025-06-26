//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 128
#define TASK_COMM_LEN 16

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct stacktrace_event
{
    __u32 pid;
    __u32 cpu_id;
    char comm[TASK_COMM_LEN];
    __s32 kstack_sz;
    __s32 ustack_sz;
    stack_trace_t kstack;
    stack_trace_t ustack;
};


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

const volatile __u32 target_pid = 0;


// 强制导出event type
const struct stacktrace_event *unused_4 __attribute__((unused));


SEC("perf_event")
int profile(void *ctx)
{

    int pid = bpf_get_current_pid_tgid() >> 32;
    int cput_id = bpf_get_smp_processor_id();
    struct stacktrace_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event),0);
    if (!event)
        return 1;
    event->pid = pid;
    event->cpu_id = cput_id;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->kstack_sz = bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    event->ustack_sz = bpf_get_stack(ctx, event->ustack, sizeof(event->ustack), BPF_F_USER_STACK);

    bpf_ringbuf_submit(event, 0);
    
    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";