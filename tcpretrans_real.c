// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Red Hat, Inc.
//
// Based on tcpconnect.c
#include <sys/resource.h>
#include <arpa/inet.h>
#include <signal.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include "tcpretrans.h"
#include "tcpretrans.skel.h"
#include "trace_helpers.h"
#include "map_helpers.h"

static void sig_int(int signo)
{
	hang_on = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
		const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void print_events_header()
{
	if (1)
		printf("%-9s", "TIME(s)");
	if (1)
		printf("%-6s", "UID");
	printf("%-6s %-12s %-2s %-16s %-16s %-4s\n",
	       "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT");
}

static void print_events(int perf_map_fd)
{
	struct perf_buffer_opts pb_opts = {
		.sample_cb = handle_event,
		.lost_cb = handle_lost_events,
	};
    // perf_buffer is supported on older kernels than ringbuf
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


int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
		.args_doc = NULL,
	};
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
		goto cleanup;
	}

    if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}

	print_events(bpf_map__fd(obj->maps.events));

cleanup:
	tcpretrans_bpf__destroy(obj);

	return err != 0;
}
