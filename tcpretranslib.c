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
#include <bpf/libbpf.h>
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

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

// This enables some libbpf debugging info.
static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	union {
		struct in_addr  x4;
		struct in6_addr x6;
	} s, d;

	if (e->af == AF_INET) {
		s.x4.s_addr = e->saddr_v4;
		d.x4.s_addr = e->daddr_v4;
	} else if (e->af == AF_INET6) {
		memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
		memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
	} else {
		warn("broken event: event->af=%d", e->af);
		return 0;
	}

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8s %-2d %-16s %s/%d %s/%d\n",
		   ts,
		   e->af == AF_INET ? 4 : 6,
		   TCPSTATE[e->state - 1],
		   inet_ntop(e->af, &s, src, sizeof(src)),
		   e->sport,
		   inet_ntop(e->af, &d, dst, sizeof(dst)),
		   e->dport);

	return 0;
}

int run()
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
	printf("%-8s %-2s %-16s %-19s %s\n",
		   "TIME", "IP", "STATE", "LOCAL", "REMOTE");
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
