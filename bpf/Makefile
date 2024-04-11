# SPDX-License-Identifier: GPL-2.0

SRCARCH := x86
HOSTPKG_CONFIG := pkg-config
CFLAGS += -g -O0 -rdynamic -Wall -Werror -I$(OUTPUT)
CFLAGS += -I/usr/include
LDLIBS += -lelf -lz -lrt -lpthread -lbpf

CLANG := $(shell which clang)
OUTPUT := $(shell pwd)
BPFDIR := $(shell pwd)
TEST_GEN_PROGS = ublk_null

# Silence some warnings when compiled with clang
ifneq ($(LLVM),)
CFLAGS += -Wno-unused-command-line-argument
endif

# Emit succinct information message describing current building step
# $1 - generic step name (e.g., CC, LINK, etc);
# $2 - optional "flavor" specifier; if provided, will be emitted as [flavor];
# $3 - target (assumed to be file); only file name will be emitted;
# $4 - optional extra arg, emitted as-is, if provided.
ifeq ($(V),1)
Q =
msg =
else
Q = @
msg = @printf '  %-8s%s %s%s\n' "$(1)" "$(if $(2), [$(2)])" "$(notdir $(3))" "$(if $(4), $(4))";
MAKEFLAGS += --no-print-directory
submake_extras := feature_display=0
endif

#VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
VMLINUX_BTF ?= /sys/kernel/btf/ublk_drv

# Define simple and short `make test_progs`, `make test_sysctl`, etc targets
# to build individual tests.
# NOTE: Semicolon at the end is critical to override lib.mk's default static
# rule for binaries.
$(notdir $(TEST_GEN_PROGS)): %: $(OUTPUT)/% ;

# LLVM's ld.lld doesn't support all the architectures, so use it only on x86
ifeq ($(SRCARCH),x86)
LLD := lld
else
LLD := ld
endif

# Determine target endianness.
IS_LITTLE_ENDIAN = $(shell $(CC) -dM -E - </dev/null | \
			grep 'define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__')
MENDIAN=$(if $(IS_LITTLE_ENDIAN),-mlittle-endian,-mbig-endian)

CLANG_SYS_INCLUDES = $(call get_sys_includes,$(CLANG))
BPF_CFLAGS = -g -Werror -D__TARGET_ARCH_$(SRCARCH) $(MENDIAN) 		\
	     -I$(INCLUDE_DIR) -I/usr/include -D __BPF_TRACING__

CLANG_CFLAGS = $(CLANG_SYS_INCLUDES) \
	       -Wno-compare-distinct-pointer-types

# Build BPF object using Clang
# $1 - input .c file
# $2 - output .o file
# $3 - CFLAGS
define CLANG_BPF_BUILD_RULE
	$(call msg,CLNG-BPF,$(TRUNNER_BINARY),$2)
	$(Q)$(CLANG) $3 -O2 --target=bpf -c $1 -mcpu=v3 -o $2
endef
# Similar to CLANG_BPF_BUILD_RULE, but with disabled alu32
define CLANG_NOALU32_BPF_BUILD_RULE
	$(call msg,CLNG-BPF,$(TRUNNER_BINARY),$2)
	$(Q)$(CLANG) $3 -O2 --target=bpf -c $1 -mcpu=v2 -o $2
endef
# Build BPF object using GCC
define GCC_BPF_BUILD_RULE
	$(call msg,GCC-BPF,$(TRUNNER_BINARY),$2)
	$(Q)$(BPF_GCC) $3 -O2 -c $1 -o $2
endef

BPFTOOL := $(shell which bpftool)
BPF_PROGS_DIR := progs
BPF_BUILD_RULE := CLANG_BPF_BUILD_RULE
BPF_SRCS := $(notdir $(wildcard $(BPF_PROGS_DIR)/*.c))
BPF_OBJS := $(patsubst %.c,$(OUTPUT)/%.bpf.o, $(BPF_SRCS))
BPF_SKELS := $(patsubst %.c,$(OUTPUT)/%.skel.h, $(BPF_SRCS))
TEST_GEN_FILES += $(BPF_OBJS)

$(BPF_PROGS_DIR)-bpfobjs := y
$(BPF_OBJS): $(OUTPUT)/%.bpf.o:				\
	     $(BPF_PROGS_DIR)/%.c			\
	     $(wildcard $(BPF_PROGS_DIR)/*.h)		\
	     $(BPF_PROGS_DIR)/vmlinux.h				\
	     $(wildcard $(BPFDIR)/*.bpf.h)			\
	     | $(OUTPUT) $(BPFOBJ)
	$(call $(BPF_BUILD_RULE),$<,$@, $(BPF_CFLAGS))

$(BPF_PROGS_DIR)/vmlinux.h: $(VMLINUX_BTF) $(BPFTOOL) | $(INCLUDE_DIR)
ifeq ($(VMLINUX_H),)
	$(call msg,GEN,,$@)
	$(Q)$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@
else
	$(call msg,CP,,$@)
	$(Q)cp "$(VMLINUX_H)" $@
endif

$(BPF_SKELS): %.skel.h: %.bpf.o $(BPFTOOL) | $(OUTPUT)
	$(call msg,GEN-SKEL,$(BINARY),$@)
	$(Q)$(BPFTOOL) gen object $(<:.o=.linked1.o) $<
	$(Q)$(BPFTOOL) gen skeleton $(<:.o=.linked1.o) name $(notdir $(<:.bpf.o=)) > $@

$(OUTPUT)/%.o: %.c $(BPF_SKELS)
	$(call msg,CC,,$@)
	$(Q)$(CC) $(CFLAGS) -c $(filter %.c,$^) $(LDLIBS) -o $@

$(OUTPUT)/%: $(OUTPUT)/%.o
	$(call msg,BINARY,,$@)
	$(Q)$(LINK.c) $^ $(LDLIBS) -o $@

EXTRA_CLEAN := $(SCRATCH_DIR) $(HOST_SCRATCH_DIR) feature bpftool	\
	$(addprefix $(OUTPUT)/,*.o *.skel.h no_alu32)
.PHONY: clean
clean:
	rm -f $(OUTPUT)/*.o $(OUTPUT)/*.skel.h $(OUTPUT)/*~ ${TEST_GEN_PROGS}
	rm -f $(BPF_PROGS_DIR)/vmlinux.h
