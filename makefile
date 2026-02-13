OUTPUT := .output
CLANG  := clang
BPFTOOL := bpftool
LIBBPF_SRC := /usr/include/bpf 
ARCH := x86
BPF_SRCS := $(wildcard */*.bpf.c)
BPF_OBJS := $(patsubst src/bpf/%.bpf.c, $(OUTPUT)/%.bpf.o, $(BPF_SRCS))
BPF_SKELS := $(patsubst src/bpf/%.bpf.c, $(OUTPUT)/%.skel.h, $(BPF_SRCS))

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	      -I$(OUTPUT) -Isrc/bpf -I/usr/include/bpf

.PHONY: all clean vmlinux

all: $(BPF_SKELS)
	@echo "successfully generated skeletons."

vmlinux: $(OUTPUT)/vmlinux.h
$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	@echo "  GEN     vmlinux.h"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT)/%.bpf.o: src/bpf/%.bpf.c | $(OUTPUT) vmlinux
	@echo "  CLANG   $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	@echo "  BPFTOOL $@"
	@$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT):
	mkdir -p $(OUTPUT)

clean:
	rm -rf $(OUTPUT)