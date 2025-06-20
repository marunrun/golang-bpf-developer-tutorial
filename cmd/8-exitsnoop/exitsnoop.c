//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "exitsnoop.h"




//
const struct event *unused_4 __attribute__((unused));


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,256 * 1024);
} rb SEC(".maps");

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct* task;
    struct event *e;
    pid_t pid,tid;
    u64 id, start_time = 0;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (u32)id;

    // 忽略线程的退出
    // 进程 id 和线程组 id 一致， 保证这里都是进程退出
    if (pid != tid)
        return 0;

    // 预留 ringbuf 的内存
    e = bpf_ringbuf_reserve(&rb, sizeof(*e),0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    start_time = BPF_CORE_READ(task,start_time);
    e->duration_ns  = bpf_ktime_get_ns() - start_time;
    e->pid = pid;
    e->ppid =  BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 将数据存储到 ringbuf
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
