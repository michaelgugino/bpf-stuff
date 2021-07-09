// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Red Hat, Inc.
#ifndef __TCPRETRANS_H
#define __TCPRETRANS_H

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

/* The maximum number of ports to filter */
#define MAX_PORTS 64

// #define TASK_COMM_LEN 16

struct event {
	union {
		__u32 saddr_v4;
		__u8 saddr_v6[16];
	};
	union {
		__u32 daddr_v4;
		__u8 daddr_v6[16];
	};
	// char task[TASK_COMM_LEN]; // garbage value
	__u64 ts_us;
	__u32 af; // AF_INET or AF_INET6
	// __u32 pid; // garbage value
	// __u32 uid; // garbage value
	__u16 dport;
    __u16 sport;
    // char state;
    int state;
};

#endif /* __TCPRETRANS_H */
