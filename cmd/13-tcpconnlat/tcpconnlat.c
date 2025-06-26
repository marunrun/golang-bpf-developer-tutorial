//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16


#define AF_INET    2
#define AF_INET6   10

struct piddata
{
    u64 ts;
    __u32 tgid;

    unsigned char comm[TASK_COMM_LEN];
};

struct event
{
    __u64 delta_us;
    __u64 ts_us;

    __u32 tgid;
    int af;


    union {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };

    unsigned char comm[TASK_COMM_LEN];

    __u16 lport;
    __u16 dport;
};

// 强制导出event type
const struct event *unused_4 __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct sock *);
    __type(value, struct piddata);
} start SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

const volatile __u64 targ_min_us = 0;
const volatile pid_t targ_tgid = 0;

static int trace_connect(struct sock *sk)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct piddata piddata = {};

    if (targ_tgid && tgid != targ_tgid)
        return 0;

    bpf_printk("get connect %d\n",tgid);
    bpf_get_current_comm(&piddata.comm, sizeof(piddata.comm));
    piddata.ts = bpf_ktime_get_ns();
    piddata.tgid = tgid;
    bpf_map_update_elem(&start, &sk, &piddata, 0);
    return 0;
}

static int handle_tcp_rcv_state_process(void *ctx, struct sock *sk)
{
    if (BPF_CORE_READ(sk, __sk_common.skc_state) != TCP_SYN_SENT)
        return 0;

    struct piddata *piddata;

    piddata = bpf_map_lookup_elem(&start, &sk);
    if (!piddata)
        return 0;
    u64 ts;
    bpf_printk("get process %d\n",piddata->tgid);

    ts = bpf_ktime_get_ns();
    s64 delta;
    delta = (s64)(ts - piddata->ts);
    if (delta < 0)
        goto clean;

    struct event event = {};

    event.delta_us = delta / 1000U;
    if (targ_min_us && event.delta_us < targ_min_us)
        goto clean;

    // 复制 comm
    __builtin_memcpy(event.comm, piddata->comm, sizeof(event.comm));

    event.ts_us = ts / 1000;
    event.tgid = piddata->tgid;
    event.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    event.af = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (event.af == AF_INET)
    {
        event.saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        event.daddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }
    else
    {
        BPF_CORE_READ_INTO(&event.saddr_v6, sk,
                           __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(&event.daddr_v6, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

clean:
    bpf_map_delete_elem(&start, &sk);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk)
{
    return trace_connect(sk);
}

SEC("kprobe/tcp_rcv_state_process")
int BPF_KPROBE(tcp_rcv_state_process, struct sock *sk)
{

    return handle_tcp_rcv_state_process(ctx, sk);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";