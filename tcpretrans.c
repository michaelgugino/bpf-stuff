// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Red Hat, Inc.
//
// Based on tcpconnect.c
#include <sys/resource.h>
#include <arpa/inet.h>
#include <argp.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

static volatile sig_atomic_t hang_on = 1;

static void sig_int(int signo)
{
	hang_on = 0;
}

// This enables some libbpf debugging info.
static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/*
event = b["ipv4_events"].event(data)
print("%-8s %-6d %-2d %-20s %1s> %-20s %s" % (
	strftime("%H:%M:%S"), event.pid, event.ip,
	"%s:%d" % (inet_ntop(AF_INET, pack('I', event.saddr)), event.lport),
	type[event.type],
	"%s:%s" % (inet_ntop(AF_INET, pack('I', event.daddr)), event.dport),
	tcpstate[event.state]))
*/

/*
static void print_events_header()
{
	if (env.print_timestamp)
		printf("%-9s", "TIME(s)");
	if (env.print_uid)
		printf("%-6s", "UID");
	printf("%-6s %-12s %-2s %-16s %-16s %-4s\n",
	       "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT");
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *event = data;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;
	static __u64 start_ts;

	if (event->af == AF_INET) {
		s.x4.s_addr = event->saddr_v4;
		d.x4.s_addr = event->daddr_v4;
	} else if (event->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, event->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, event->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: event->af=%d", event->af);
		return;
	}

	if (env.print_timestamp) {
		if (start_ts == 0)
			start_ts = event->ts_us;
		printf("%-9.3f", (event->ts_us - start_ts) / 1000000.0);
	}

	if (env.print_uid)
		printf("%-6d", event->uid);

	printf("%-6d %-12.12s %-2d %-16s %-16s %-4d\n",
	       event->pid, event->task,
	       event->af == AF_INET ? 4 : 6,
	       inet_ntop(event->af, &s, src, sizeof(src)),
	       inet_ntop(event->af, &d, dst, sizeof(dst)),
	       ntohs(event->dport));
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
*/

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-5s %-7d %-16d\n", ts, "EXEC", e->pid, e->af);

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct tcpretrans_bpf *obj;
	int err;

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

	err = tcpretrans_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = tcpretrans_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		// TODO: we can use this as a crude method for detecting the presence
		// of the trace point, but how to load a different SKEL?
		goto cleanup;
	}

    if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}
	/*
	while (hang_on) {
		sleep(1);
	}
	*/
	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("%-8s %-5s %-7s %-16s %s\n",
		   "TIME", "EVENT", "PID", "COMM", "FILENAME");
	while (hang_on) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}
	// print_events(bpf_map__fd(obj->maps.events));

cleanup:
	ring_buffer__free(rb);
	tcpretrans_bpf__destroy(obj);

	return err != 0;
}
