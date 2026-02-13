#include "flow_map.h"

#define REDIRECT_PORT 2333

SEC("tc")
int ingress_redirect(struct __sk_buff *skb)
{
    struct ethhdr eth;
    struct iphdr ip;
    struct tcphdr tcp;

    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
        return TC_ACT_OK;
    if (eth.h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip)) < 0)
        return TC_ACT_OK;
    if (ip.protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 ip_hdr_len = ip.ihl * 4;
    __u32 tcp_off = sizeof(eth) + ip_hdr_len;
    if (bpf_skb_load_bytes(skb, tcp_off, &tcp, sizeof(tcp)) < 0)
        return TC_ACT_OK;

    // Check if packet from one of the IPs in the filter map
    __u64 *start_time = bpf_map_lookup_elem(&filter_map, &ip.saddr);
    if (!start_time)
        return TC_ACT_OK;

    __u64 now = bpf_ktime_get_ns();
    if (now - *start_time > 3600000000000ULL) {
        // Expired (1 hour = 3600 * 10^9 ns)
        bpf_map_delete_elem(&filter_map, &ip.saddr);
        return TC_ACT_OK;
    }

    struct flow_info f = {
        .original_port = tcp.dest,
        .redirected_port = __constant_htons(REDIRECT_PORT),
        .id = (__u32)*start_time // Use part of timestamp as ID
    };

    bpf_map_update_elem(&flow_map, &ip.saddr, &f, BPF_ANY);

    if (bpf_skb_store_bytes(skb,
            tcp_off + offsetof(struct tcphdr, dest),
            &f.redirected_port, sizeof(f.redirected_port), 0) < 0)
        return TC_ACT_SHOT;

    bpf_l4_csum_replace(skb,
        tcp_off + offsetof(struct tcphdr, check),
        tcp.dest, f.redirected_port, sizeof(f.redirected_port));

    bpf_printk("Ingress: IP %x redirected to port %d, ID %d\n",
               ip.saddr, __builtin_bswap16(f.redirected_port), f.id);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
