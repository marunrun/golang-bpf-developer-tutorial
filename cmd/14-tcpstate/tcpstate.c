//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MAX_ENTRIES 10240
#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16

struct event
{
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    __u64 skaddr;
    __u64 ts_us;
    __u64 delta_us;
    __u32 pid;
    int oldstate;
    int newstate;
    __u16 family;
    __u16 sport;
    __u16 dport;
    unsigned char task[TASK_COMM_LEN];
};

const struct event *unused_4 __attribute__((unused));

// 保存需要过滤的源端口
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} sports SEC(".maps");

// 保存需要过滤的目标端口
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u16);
    __type(value, __u16);
} dports SEC(".maps");

// 保存sock的最后一次变动时间
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct sock *);
    __type(value, __u64);
} timestamps SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

const volatile __u16 target_family = 0;
const volatile bool filter_by_sport = false;
const volatile bool filter_by_dport = false;

SEC("tp/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{

    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;
    __u16 family = ctx->family;

    struct sock *sk = (struct sock *)ctx->skaddr;

    // 过滤 tcp 协议
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    // 判断是否指定过滤 ipv4 或者 ipv6
    if (target_family && target_family != family)
        return 0;

    // 判断是否过滤源端口
    if (filter_by_sport && !bpf_map_lookup_elem(&sports, &sport))
        return 0;

    // 判断是否过滤目标端口
    if (filter_by_dport && !bpf_map_lookup_elem(&dports, &dport))
        return 0;

    // 计算间隔时间
    __u64 *tsp, ts, delta_us;
    tsp = bpf_map_lookup_elem(&timestamps, &sk);
    ts = bpf_ktime_get_ns();
    if (!tsp)
    {
        delta_us = 0;
    }
    else
    {
        delta_us = (ts - *tsp) / 1000;
    }
    struct event event = {};

    event.skaddr = (__u64)sk;
    event.ts_us = ts / 1000;
    event.delta_us = delta_us;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.oldstate = ctx->oldstate;
    event.newstate = ctx->newstate;
    event.family = family;
    event.sport = sport;
    event.dport = dport;
    bpf_get_current_comm(&event.task, sizeof(event.task));

    if (family == AF_INET)
    {
        // ipv4
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_daddr);
    }
    else
    {
        // ipv6
        bpf_probe_read_kernel(&event.saddr, sizeof(event.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&event.daddr, sizeof(event.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    if (ctx->newstate == TCP_CLOSE)
        bpf_map_delete_elem(&timestamps, &sk);
    else
        bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);

    return 0;
}

char LICENSE[] SEC("licenses") = "GPL";