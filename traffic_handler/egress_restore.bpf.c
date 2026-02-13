#include "flow_map.h"

SEC("tc")
int egress_restore(struct __sk_buff *skb)
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

    // Lookup using client IP (destination of outgoing packet)
    struct flow_info *f = bpf_map_lookup_elem(&flow_map, &ip.daddr);
    if (!f)
        return TC_ACT_OK;

    // Only process if packet uses redirected port
    if (tcp.source != f->redirected_port)
        return TC_ACT_OK;

    __u16 old_port = tcp.source;
    __u16 restored_port = f->original_port;

    if (bpf_skb_store_bytes(skb,
            tcp_off + offsetof(struct tcphdr, source),
            &restored_port, sizeof(restored_port), 0) < 0)
        return TC_ACT_SHOT;

    bpf_l4_csum_replace(skb,
        tcp_off + offsetof(struct tcphdr, check),
        old_port, restored_port, sizeof(restored_port));

    bpf_printk("Egress: Restored IP %x to original port %d (ID %d)\n",
               ip.daddr, __builtin_bswap16(restored_port), f->id);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
