#!/bin/bash
set -e

IFACE="ens3"
BPF_FS="/sys/fs/bpf"

# Compile first
cd /workspace
make clean
make

# Cleanup
echo "[+] Cleaning previous BPF..."
bpftool net detach xdp dev $IFACE || true
tc qdisc del dev $IFACE clsact || true
rm -f $BPF_FS/ip_check $BPF_FS/ingress_redirect $BPF_FS/egress_restore
rm -f $BPF_FS/flow_map $BPF_FS/filter_map

# Ensure bpffs mounted
mount -t bpf bpf $BPF_FS || true

echo "[+] Loading BPF programs..."

# Load XDP (pins maps automatically due to PIN_BY_NAME in C code, but we must specify pinpath for loader to know where root is?)
# Actually bpftool prog load ... pinning maps usually requires 'pinmaps' arg
# But if C code has pinning, libbpf honors it relative to /sys/fs/bpf?
# Let's specify explicitly to be safe.

# Load ip_check (XDP)
# Note: we pin maps to $BPF_FS so they are shared
bpftool prog load .output/ip_check.bpf.o $BPF_FS/ip_check pinmaps $BPF_FS
bpftool net attach xdp pinned $BPF_FS/ip_check dev $IFACE

# Load ingress_redirect (TC)
# We need to make sure it reuses the pinned maps. 
# bpftool should handle this if map names match and are found in pinmaps path.
bpftool prog load .output/ingress_redirect.bpf.o $BPF_FS/ingress_redirect type classifier pinmaps $BPF_FS

# Attach Ingress
tc qdisc add dev $IFACE clsact || true
tc filter add dev $IFACE ingress bpf da object-pinned $BPF_FS/ingress_redirect

# Load egress_restore (TC)
bpftool prog load .output/egress_restore.bpf.o $BPF_FS/egress_restore type classifier pinmaps $BPF_FS

# Attach Egress
tc filter add dev $IFACE egress bpf da object-pinned $BPF_FS/egress_restore

echo "[+] BPF programs loaded!"
bpftool prog show
bpftool map show

echo "[+] Starting Agent..."
./.output/rkit-agent &
echo "[+] Agent started with PID $!"
