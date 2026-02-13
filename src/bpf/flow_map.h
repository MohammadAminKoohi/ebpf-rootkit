#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

// This struct stores flow info per IP
struct flow_info {
    __u16 original_port;      // original TCP dest port
    __u16 redirected_port;    // redirected TCP port
    __u32 id;                 // flow ID
};

// Map shared between ingress and egress
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      // IP of client
    __type(value, struct flow_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_map SEC(".maps");

// Map for filtered IPs (populated by another eBPF program)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);      // IP to track
    __type(value, __u64);    // Timestamp (ns)
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} filter_map SEC(".maps");
