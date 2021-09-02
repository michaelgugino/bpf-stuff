/* SPDX-License-Identifier: GPL-2.0 */

/*
 * tcpretrans  Trace IPv4 and IPv6 tcp retransmit events
 *
 * Copyright (c) 2020 Anton Protopopov
 * Copyright (c) 2021 Red Hat, Inc.
 *
 * Based on tcpconnect.c by Anton Protopopov and
 * tcpretrans(8) from BCC by Brendan Gregg
 * 15-Jul-2021   Michael Gugino   Created this.
 */
#include <sys/resource.h>
#include <arpa/inet.h>
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "libtcpretrans.h"
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"


// extern informs the compiler that this function will be satifies at linking
// time which in our case is handled by cgo.
extern void gocb(int);

#define warn(...) fprintf(stderr, __VA_ARGS__)

const char* tppath = "/sys/kernel/debug/tracing/events/tcp/tcp_retransmit_skb/id";

const char* TCPSTATE[] = {
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
	"NEW_SYN_RECV"};


static volatile sig_atomic_t hang_on = 1;

static void sig_int(int signo)
{
	hang_on = 0;
}

static struct env {
	bool verbose;
	bool count;
	bool lossprobe;
	bool kprobe;
} env = {};

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_events_header()
{
	printf("%-8s %-6s %-2s %-20s %1s> %-20s %-12s %-10s\n", "TIME", "PID", "IP",
		"LADDR:LPORT", "T", "RADDR:RPORT", "STATE", "SEQ");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{

	gocb(999);
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	char remote[INET6_ADDRSTRLEN + 6];
	char local[INET6_ADDRSTRLEN + 6];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (e->af == AF_INET) {
		memcpy(&s.x4.s_addr, e->saddr, sizeof(s.x4.s_addr));
		memcpy(&d.x4.s_addr, e->daddr, sizeof(d.x4.s_addr));
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, e->daddr, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: event->af=%d", e->af);
		return;
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	sprintf(local, "%s:%d", inet_ntop(e->af, &s, src, sizeof(src)), e->sport);
	sprintf(remote, "%s:%d", inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport));

	printf("%-8s %-6d %-2d %-20s %1s> %-20s %-12s %-10u\n",
		   ts,
		   e->pid,
		   e->af == AF_INET ? 4 : 6,
		   local,
		   e->type == RETRANSMIT ? "R" : "L",
		   remote,
		   TCPSTATE[e->state - 1],
	       e->seq);
	fflush(stdout);
	return;
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

static void print_events(int perf_map_fd)
{
	struct perf_buffer_opts pb_opts = {
		.sample_cb = handle_event,
		.lost_cb = handle_lost_events,
	};
	struct perf_buffer *pb = NULL;
	int err;

	pb = perf_buffer__new(perf_map_fd, 128, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	print_events_header();
	while (hang_on) {
		err = perf_buffer__poll(pb, 100);
		if (err < 0 && errno != EINTR) {
			warn("Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	perf_buffer__free(pb);
}

int run()
{
	struct tcpretrans_bpf *obj;
	int err, tpmissing;
	struct bpf_program *prog;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %s\n", strerror(errno));
		return 1;
	}

	obj = tcpretrans_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	// bpf will load non-existant trace points but fail at the attach stage, so
	// check to ensure our tp exists before we load it.
	tpmissing = access(tppath, F_OK);

	if (tpmissing || env.kprobe) {
		if (!env.kprobe)
			warn("tcp_retransmit_skb tracepoint not found, falling back to kprobe");
		prog = bpf_object__find_program_by_name(obj->obj, "tracepoint__tcp__tcp_retransmit_skb");
		err = bpf_program__set_autoload(prog, false);
		if (err) {
			warn("Unable to set autoload for tcp_retransmit_skb\n");
			return err;
		}
	} else {
		prog = bpf_object__find_program_by_name(obj->obj, "tcp_retransmit_skb");
		err = bpf_program__set_autoload(prog, false);
		if (err) {
			warn("Unable to set autoload for tcp_send_loss_probe\n");
			return err;
		}
	}

	err = tcpretrans_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpretrans_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}
	printf("Tracing retransmits ... Hit Ctrl-C to end\n");
	print_events(bpf_map__fd(obj->maps.events));

cleanup:
	tcpretrans_bpf__destroy(obj);

	return err != 0;
}
