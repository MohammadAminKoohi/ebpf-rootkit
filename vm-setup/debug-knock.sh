#!/usr/bin/env bash
# Debug XDP/TC knock: see what's happening to packets.
# Run on the TARGET (agent) machine: sudo ./vm-setup/debug-knock.sh

set -e
IFACE="${1:-eth0}"

echo "=== 1. BPF programs (XDP + TC) attached to $IFACE ==="
echo "XDP:"
ip link show "$IFACE" | grep -E "xdp|prog" || true
echo ""
echo "TC ingress/egress:"
tc filter show dev "$IFACE" ingress 2>/dev/null | head -20 || true
tc filter show dev "$IFACE" egress 2>/dev/null | head -20 || true

echo ""
echo "=== 2. BPF trace (bpf_printk) - run in another terminal BEFORE sending magic packet ==="
echo "  sudo cat /sys/kernel/debug/tracing/trace_pipe"
echo "  Then run CLI from your laptop. You should see:"
echo "    - 'XDP: magic packet saddr=0x...' when magic packet arrives"
echo "    - 'Ingress: IP ... redirected' when connect packet is rewritten"
echo "    - 'Egress: Restored...' when agent sends reply"
echo ""

echo "=== 3. filter_map (IPs with magic-packet open window) ==="
if command -v bpftool &>/dev/null; then
    FILTER_ID=$(bpftool map list 2>/dev/null | grep "filter_map" | head -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$FILTER_ID" ]; then
        echo "  bpftool map dump id $FILTER_ID"
        bpftool map dump id "$FILTER_ID" 2>/dev/null || echo "(empty or error)"
        echo "  Key=client IPv4 (hex), value=timestamp (ns). Run CLI, then run this again to see new entry."
    else
        echo "  filter_map not found (agent not running or no XDP)"
    fi
fi

echo ""
echo "=== 4. flow_map (IP -> original_port, redirected_port) ==="
if command -v bpftool &>/dev/null; then
    FLOW_ID=$(bpftool map list | grep -E "flow_map|hash" | tail -1 | awk '{print $1}' | tr -d ':')
    if [ -n "$FLOW_ID" ]; then
        echo "bpftool map dump id $FLOW_ID"
        bpftool map dump id "$FLOW_ID" 2>/dev/null || echo "(no flow_map)"
    fi
fi

echo ""
echo "=== 5. Packet capture (run before connecting) ==="
echo "  sudo tcpdump -i $IFACE -n 'tcp port 2332 or tcp port 2333' -c 20"
echo "  (Shows packets; after rewrite, you'll see 2333 on wire from agent side)"
