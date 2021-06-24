# Notes

## tracepoints

Things you can target BPF programs against: kprobes, kretprobes, tracepoints,
and likely other things I'm not familiar with yet.

perf is a good place to list tracepoints.  These tracepoints represent a stable
API to build programs against, kprobes and kretprobes will be much less stable.

If perf isn't installed on the target host, you can look at
`/sys/kernel/debug/tracing/events/%s/%s` for available tracepoints.

`/sys/kernel/debug/` is an empty dir by default in OpenShift debug containers,
so need to chroot to /host to utilize tools that consume trace points or
ensure you bind mount that directory into the container.

http://www.brendangregg.com/blog/2018-03-22/tcp-tracepoints.html

How to write tracepoints: https://lwn.net/Articles/379903/  This seems pretty
straight forward provided you have an understanding of what data structures
you want to target.  For example, here's the tcp_retransmit_skb tracepoint:
https://github.com/torvalds/linux/commit/e086101b150ae8e99e54ab26101ef3835fa9f48d#

There are a lot of notes in upstream BPF documentation that specifies a kernel
version newer than what ships in the latest RHEL 8 release (kernels 5.5 and
newer are often mentioned).  Some of this functionality might have been
backported into 8.3 (and possibly older), TBD.

## tcp_retransmit_skb tracepoint info

I was going through the blog post section
https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#tracepoints
and I checked in the included vmlinux.h to determine what datastructure I should
use for tcp_retransmit_skb trace point. The default naming convention yielded no results.

There is still a tracepoint at `tp/tcp/tcp_retransmit_skb`, but the corresponding
datastructure was converted to `tcp_event_sk_skb`
via: https://github.com/torvalds/linux/commit/f6e37b25413cf636369668652e9752ee77c7d9f7

Looking back in vmlinux.h, I noticed `trace_event_raw_tcp_event_sk_skb` was
indeed present.

## BPF_MAP_TYPE_RINGBUF

The bcc repo doesn't ship with a new enough vmlinux.h to support `BPF_MAP_TYPE_RINGBUF`
However, this structure has been backported to RHEL 8.4, so I can use it fine.
Current Fedora releases contain it as well (I'm on F33 ATM).

`./libbpf-tools/bin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > libbpf-tools/x86/vmlinux_$(uname -r).h`
