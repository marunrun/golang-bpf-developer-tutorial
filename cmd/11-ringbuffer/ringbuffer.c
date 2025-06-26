//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");




struct event
{
    unsigned long long duration_ns;    // 8字节，8字节对齐
    int pid;                          // 4字节
    int ppid;                         // 4字节
    unsigned int exit_code;           // 4字节
    bool exit_event;                  // 1字节
    unsigned char comm[TASK_COMM_LEN];        // 16字节
    unsigned char filename[MAX_FILENAME_LEN]; // 256字节
};

const volatile unsigned long long  min_duration_ns = 0;

// 强制导出event type
const struct event *unused_4 __attribute__((unused));

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    pid_t pid;
    u64 ts;
    struct event *e;
    unsigned fname_off;


    // 记录 pid 对应的开始时间
    pid =  bpf_get_current_pid_tgid() >> 32;
    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);


    if (min_duration_ns)
        return 0;

    // 如果没有限制时间
    e = bpf_ringbuf_reserve(&rb,sizeof(*e),0);
    if (!e)
        return 0;

    task = (struct task_struct*)bpf_get_current_task();

    // 非退出事件
    e->exit_event = false;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task,real_parent,tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    fname_off = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

    // 提交数据
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *task;
    struct event *e;
    pid_t pid, tid;
    u64 id  ,*start_ns , duration_ns = 0;

    id = bpf_get_current_pid_tgid();

    pid = id >> 32;
    tid = (u32)id;

    // 过滤 线程退出事件
    if (pid != tid)
        return 0;


    start_ns = bpf_map_lookup_elem(&exec_start, &pid);
    if (start_ns)
        duration_ns = bpf_ktime_get_ns() - *start_ns;
    else if (min_duration_ns)
        return 0;

    bpf_map_delete_elem(&exec_start, &pid);


    // 如果没有到达 min_duration_ns 则返回
    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    e->exit_event = true;
    e->duration_ns = duration_ns;
    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";