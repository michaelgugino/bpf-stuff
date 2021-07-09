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
    const struct sock *skp;
    __u16 dport;
    __u16 sport;
    __u32 family;
    // char state;
    int state;

    // Reserve memory for our event, or return 0 if no space
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;


    /*
    const struct sk_buff *skb = BPF_CORE_READ(ctx, skbaddr);
    u64 pid2 = 0;
    struct pid *p;
    if (skb != NULL) {
        bpf_printk("skb not null");
        struct fown_struct f_owner = BPF_CORE_READ(skb,sk,sk_socket,file,f_owner);
        p = f_owner.pid;

        // Complier complains about this.
        // p = BPF_CORE_READ(skb,sk,sk_socket,file,f_owner,pid)

        // This always prints zero?
        bpf_printk("p pointer %d", p);
        if (p) {
            bpf_printk("p pointer not null");
            pid2 = BPF_CORE_READ(p,numbers[0].nr);
        }
    }
    bpf_printk("BPF PID: %d", pid2);
    */

    // These values are garbage
    /*
    u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->task, sizeof(e->task));
    */

    skp = BPF_CORE_READ(ctx, skaddr);
    family = BPF_CORE_READ(skp, __sk_common.skc_family);
    e->af = family;
    e->ts_us = bpf_ktime_get_ns() / 1000;
    // __sk_common.skc_dport is in network byte order
    // BPF_CORE_READ_INTO(&dport, skp, __sk_common.skc_dport);

    // tcp_event_sk_skb.dport already in host byte order
    BPF_CORE_READ_INTO(&dport, ctx, dport);
	e->dport = dport;
    BPF_CORE_READ_INTO(&sport, ctx, sport);
    e->sport = sport;
    // state = BPF_CORE_READ(skp, __sk_common.skc_state);
    state = BPF_CORE_READ(ctx, state);
    e->state = state;

    // The following doesn't work as it throws invalid memory access error
    // "R1 invalid mem access 'inv'"
    // u16 family = skp->__sk_common.skc_family;
    if (family == AF_INET) {
        bpf_printk("BPF for ipv4\n");
        e->saddr_v4 = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        e->daddr_v4 = BPF_CORE_READ(skp, __sk_common.skc_daddr);

    } else if (family == AF_INET6) {
        bpf_printk("BPF for ipv6\n");
        BPF_CORE_READ_INTO(e->saddr_v6, skp,
                   __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        BPF_CORE_READ_INTO(e->daddr_v6, skp,
                   __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
