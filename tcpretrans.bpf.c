// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Red Hat
//
// Based on tcpretrans(8) from BCC by Brendan Gregg
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "maps.bpf.h"
#include "tcpretrans.h"

SEC(".rodata") int filter_ports[MAX_PORTS];
const volatile int filter_ports_len = 0;
const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;
const volatile bool do_count = 0;

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

/* BPF ringbuf map */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

/*
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");


static __always_inline void
trace_v4(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
	struct event event = {};

	event.af = AF_INET;
	event.pid = pid;
	event.uid = bpf_get_current_uid_gid();
	event.ts_us = bpf_ktime_get_ns() / 1000;
	BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_daddr);
	event.dport = dport;
	bpf_get_current_comm(event.task, sizeof(event.task));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
}

static __always_inline void
trace_v6(struct pt_regs *ctx, pid_t pid, struct sock *sk, __u16 dport)
{
	struct event event = {};

	event.af = AF_INET6;
	event.pid = pid;
	event.uid = bpf_get_current_uid_gid();
	event.ts_us = bpf_ktime_get_ns() / 1000;
	BPF_CORE_READ_INTO(&event.saddr_v6, sk,
			   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	BPF_CORE_READ_INTO(&event.daddr_v6, sk,
			   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
	event.dport = dport;
	bpf_get_current_comm(event.task, sizeof(event.task));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));
}
*/

SEC("tp/tcp/tcp_retransmit_skb")
int tracepoint__tcp__tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb* ctx) {
    bpf_printk("BPF triggered from tcp_retransmit_skb\n");

    struct event *e;

    // Reserve memory for our event, or return 0 if no space
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

    // u32 pid = bpf_get_current_pid_tgid() >> 32;
    // pull in details
    // const struct sock *skp = (const struct sock *)ctx->skaddr;
    const struct sock *skp = BPF_CORE_READ(ctx, skaddr);
    u32 family = BPF_CORE_READ(skp, __sk_common.skc_family);
    e->af = family;
    e->pid = 7;
    // The following doesn't work as it throws invalid memory access error
    // "R1 invalid mem access 'inv'"
    // u16 family = skp->__sk_common.skc_family;
    /*
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;
    */
    if (family == AF_INET) {
        bpf_printk("BPF for ipv4\n");

    } else if (family == AF_INET6) {
        bpf_printk("BPF for ipv6\n");
    }
    /*
    // else drop
    return 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    if (ip_ver == 4)
        trace_v4(ctx, pid, sk, dport);
    else
        trace_v6(ctx, pid, sk, dport);
    */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
