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

## PID garbage

While possibly other tracepoints and kernel probes will yield useful (userspace)
process ID information, tcp events often do not.

## Dynamic lib build

libbpf is compiled statically by default, instead of being a shared lib.

```
# modify makefile and build libbpf in dynamic mode.
# modify makefile and build bpf helpers with -fpic
# first, we compile our dynamic lib
cc -Wall -fpic -I.output  -I../src/cc/libbpf/include/uapi/ -c tcpretranslib.c -o .output/tcpretranslib.o
# next, we link all out our code when creating the .so
cc -shared -o .output/libtcpretranslib.so .output/tcpretranslib.o -lelf .output/errno_helpers.o .output/map_helpers.o .output/syscall_helpers.o .output/uprobe_helpers.o .output/trace_helpers.o -L .output -lbpf
# finally, we compile a program that uses our shared lib.
cc -Wall -o tcpretransmain tcpretransmain.c -ltcpretranslib -L.output
```

The above will result in creating a shared lib which depends on a libbpf.so
installed somewhere on your system.

If you want to have a more portable shared lib without having to ship/install
libbpf.so, you can modify the libbpf Makefile itself and run the following
step instead:
```
cc -shared -o .output/libtcpretranslib.so .output/tcpretranslib.o -lelf .output/errno_helpers.o .output/map_helpers.o .output/syscall_helpers.o .output/uprobe_helpers.o .output/trace_helpers.o -L .output -Wl,--no-undefined -lz .output/libbpf.a
```

This second method is probably totally unnecessary in most cases.  If you're
already creating a shared library, you're probably shipping more than one binary
and it's not a big deal to ship libbpf and your shared lib together with
whatever is consuming them.

# cgo info

Helpful steps: https://github.com/lxwagn/using-go-with-c-libraries

Compiling as a static library.

```
cc -Wall -I.output  -I../src/cc/libbpf/include/uapi/ -c libtcpretrans.c -o .output/libtcpretrans.o

ar -rvs .output/libtcpretrans.a .output/libbpf/staticobjs/*.o .output/trace_helpers.o .output/syscall_helpers.o .output/errno_helpers.o .output/map_helpers.o .output/uprobe_helpers.o .output/libtcpretrans.o
```

Checkout main.go for the steps to link and utilize the code.
Just use `go build` to build.

# cgo building

Now there is a Makefile in libbpf-tools.  Just make that, then build main.go.
