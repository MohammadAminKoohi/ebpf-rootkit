#include "flow_map.h"

#define ONE_HOUR_NS (3600ULL * 1000000000ULL)

SEC("xdp")
int xdp_tcp_window_timer(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    /* Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* IP */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* TCP */
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u16 win = __builtin_bswap16(tcp->window);

    if (win == 54321) {
        bpf_map_update_elem(&filter_map, &ip->saddr, &now, BPF_ANY);
        bpf_printk("XDP: magic packet saddr=0x%x (add to filter_map)\n", __builtin_bswap32(ip->saddr));
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
