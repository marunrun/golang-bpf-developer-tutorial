//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct data_t
{
    __u32 cpu;
    __u32 pid;
    __u64 ts;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, struct data_t);
} data_map SEC(".maps");

const struct data_t *unused_4 __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} perf_map SEC(".maps");

const volatile __u32 time = 0;

static int gc_start(struct pt_regs *ctx)
{
    struct data_t data = {};

    data.cpu = bpf_get_smp_processor_id();
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&data_map, &data.pid, &data, BPF_ANY);

    return 0;
}

static int gc_end(struct pt_regs *ctx)
{
    struct data_t data = {};
    struct data_t *dp;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    dp = bpf_map_lookup_elem(&data_map, &data.pid);
    if (!dp)
        return 0;

    data.ts = bpf_ktime_get_ns();
    data.cpu = bpf_get_smp_processor_id();

    __u32 val = data.ts - dp->ts;

    if (val > time)
    {
        data.ts = val;
        bpf_perf_event_output(ctx, &perf_map, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    bpf_map_delete_elem(&data_map, &data.pid);

    return 0;
}

SEC("uprobe/hotspot/gc__begin")
int handle_gc_start(struct pt_regs *ctx)
{
    bpf_printk("gc_start");
    return gc_start(ctx);
}



SEC("uprobe/hotspot/gc__end")
int handle_gc_end(struct pt_regs *ctx)
{
    bpf_printk("gc_end");
    return gc_end(ctx);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
