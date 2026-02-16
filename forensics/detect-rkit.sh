#!/usr/bin/env bash
# Detection script for rkit/ebpf-rootkit (LinkPro-style)
# Checks for: LD_PRELOAD hooks, hidden eBPF, backdoor port, persistence artifacts.
#
# NOTE: If rootkit is active, ld.so.preload hides many artifacts. Run from
#       recovery/single-user or with preload cleared for full detection.
#       Some checks (ss, /sys/fs/bpf) bypass the hooks.

set -e
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

found=0

check() {
    if [ "$1" = "0" ] || [ -n "$2" ]; then
        echo -e "${RED}[FOUND]${NC} $3"
        found=1
    fi
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo "=== rkit/ebpf-rootkit detection ==="
echo ""

echo "--- 1. LD_PRELOAD ---"
if [ -f /etc/ld.so.preload ]; then
    content=$(tr -d '\0' < /etc/ld.so.preload 2>/dev/null | tr -d '\n' | xargs)
    if [ -n "$content" ]; then
        check 1 "$content" "ld.so.preload contains: $content"
        if echo "$content" | grep -qE "libld\.so|getdents_preload"; then
            check 1 1 "Suspicious preload (libld.so / getdents_preload - common rootkit)"
        fi
    else
        warn "ld.so.preload exists but could not read (may be hidden by rootkit)"
    fi
fi

echo ""
echo "--- 2. Listening port 2333 (backdoor) ---"
if command -v ss &>/dev/null; then
    if ss -tlnp 2>/dev/null | grep -qE ':2333\s|:2333$'; then
        check 1 1 "Port 2333 listening (rkit backdoor port)"
        ss -tlnp 2>/dev/null | grep -E ':2333\s|:2333$' || true
    fi
fi

echo ""
echo "--- 3. BPF artifacts ---"
[ -d /sys/fs/bpf/fire ] && check 1 1 "/sys/fs/bpf/fire exists (rkit knock/BPF pinning)"
if command -v bpftool &>/dev/null; then
    if bpftool prog list 2>/dev/null | grep -qE "xdp_tcp_window|ingress_redirect|egress_restore"; then
        check 1 1 "Suspicious BPF programs (knock/redirect)"
    fi
fi

echo ""
echo "--- 4. Process check ---"
# rkit-agent may be hidden from getdents; we only see non-hidden pids
for pid in $(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n 2>/dev/null); do
    [ -r /proc/$pid/cmdline ] || continue
    cmd=$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)
    if echo "$cmd" | grep -qE "rkit-agent|\.tmp~data\.resolveld"; then
        check 1 1 "Suspicious process pid=$pid: $cmd"
    fi
done

echo ""
echo "--- 5. XDP/TC on interface ---"
for iface in eth0 ens5 enp0s3; do
    if ip link show "$iface" 2>/dev/null | grep -q "xdp"; then
        warn "XDP attached to $iface (could be rkit knock)"
    fi
done

echo ""
if [ $found -eq 1 ]; then
    echo -e "${RED}*** INDICATORS FOUND - possible rkit/ebpf-rootkit ***${NC}"
    echo "For full scan, boot single-user or run with: sudo bash -c 'echo \"\" > /etc/ld.so.preload' then re-run"
    exit 1
else
    echo -e "${GREEN}No obvious indicators found.${NC}"
    echo "(Rootkit may hide artifacts; ss/netlink checks bypass some hiding)"
    exit 0
fi
