OUTPUT := .output
CLANG  := clang
BPFTOOL := bpftool
LIBBPF_SRC := /usr/include/bpf 
ARCH := x86
APP := $(OUTPUT)/rkit-agent
CLI := cli

BPF_SRCS := $(wildcard src/bpf/*.c)
BPF_OBJS := $(patsubst src/bpf/%.c, $(OUTPUT)/%.bpf.o, $(BPF_SRCS))
BPF_SKELS := $(patsubst src/bpf/%.c, $(OUTPUT)/%.skel.h, $(BPF_SRCS))
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
          -I$(OUTPUT) -Isrc/bpf -I/usr/include/bpf \
		  -I/usr/include/$(shell uname -m)-linux-gnu

CFLAGS := -g -O2 -Wall -I$(OUTPUT)
LDFLAGS := -lbpf -lelf -lz -lssl -lcrypto

.SECONDARY:

.PHONY: all clean vmlinux

all: $(APP) $(CLI)
	@echo "[+] Build complete: $(APP)"

$(CLI): src/cli.c 
	@$(CLANG) $(CFLAGS) $< -o $@

$(APP): src/main.c $(BPF_SKELS) | $(OUTPUT)
	@echo "  CC      $@"
	@$(CLANG) $(CFLAGS) $< -o $@ $(LDFLAGS)

$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	@echo "  GEN     vmlinux.h"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT)/%.bpf.o: src/bpf/%.c | $(OUTPUT) $(OUTPUT)/vmlinux.h
	@echo "  CLANG   $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	@echo "  BPFTOOL $@"
	@$(BPFTOOL) gen skeleton $< > $@

$(OUTPUT):
	mkdir -p $(OUTPUT)

clean:
	rm -rf $(OUTPUT)
	rm -f $(CLI)