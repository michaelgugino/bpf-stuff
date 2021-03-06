# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := .output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bin/bpftool
LIBBPF_SRC := $(abspath ../src/cc/libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
INCLUDES := -I$(OUTPUT) -I../src/cc/libbpf/include/uapi
CFLAGS := -g -O2 -Wall
INSTALL ?= install
prefix ?= /usr/local
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')

ifeq ($(wildcard $(ARCH)/),)
$(error Architecture $(ARCH) is not supported yet. Please open an issue)
endif

APPS = \
	libtcpretrans \
	#

COMMON_OBJ = \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/syscall_helpers.o \
	$(OUTPUT)/errno_helpers.o \
	$(OUTPUT)/map_helpers.o \
	$(OUTPUT)/uprobe_helpers.o \
	#

.PHONY: all
all: $(APPS)

ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s %s%s\n' "$(1)" "$(notdir $(2))" "$(if $(3), $(3))";
MAKEFLAGS += --no-print-directory
endif

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@


$(OUTPUT)/tcpretrans.skel.h: $(OUTPUT)/tcpretrans.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT)/tcpretrans.bpf.o: tcpretrans.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(ARCH)/vmlinux.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     -I$(ARCH)/ $(INCLUDES) -c $(filter %.c,$^) -o $@ &&      \
	$(LLVM_STRIP) -g $@

$(OUTPUT)/%.o: %.c $(wildcard %.h) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch]) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build libtcpretrans.
$(OUTPUT)/libtcpretrans.a:
	$(Q)ar -rvs .output/libtcpretrans.a .output/libbpf/staticobjs/*.o \
	.output/trace_helpers.o .output/syscall_helpers.o .output/errno_helpers.o \
	.output/map_helpers.o .output/uprobe_helpers.o .output/libtcpretrans.o

.PHONY: libtcpretrans
libtcpretrans: \
	$(LIBBPF_OBJ) \
	$(OUTPUT)/tcpretrans.skel.h \
	$(COMMON_OBJ) \
	$(OUTPUT)/libtcpretrans.o \
	$(OUTPUT)/libtcpretrans.a


# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
