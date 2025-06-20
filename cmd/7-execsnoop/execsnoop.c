//go:build ignore

#include "execsnoop.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

typedef struct event event_t;


// 这行代码的作用是 强制编译器在目标文件中保留 `struct event` 的调试信息和类型定义。
// 然后使用 `bpf2go -type event` 可以将这个 struct 导出到 golang 代码里使用
const struct event *unused_4 __attribute__((unused));

struct 
{
    __uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
   
} events SEC(".maps");



SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    u64 id;
    pid_t  tgid;
    event_t event = {0};

    struct task_struct *task;

    uid_t  uid = (u32)bpf_get_current_uid_gid();
    id = bpf_get_current_pid_tgid();
    tgid = id >> 32;

    event.pid = tgid;
    event.uid = uid;

    task = (struct task_struct *)bpf_get_current_task();
    event.ppid = BPF_CORE_READ(task,real_parent,tgid);
    bpf_probe_read_str(&event.comm, sizeof(event.comm), (void*)ctx->args[0]);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";