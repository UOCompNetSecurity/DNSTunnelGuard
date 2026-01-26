
#include "vmlinux.h"
#include <bpf/bpf_helpers.h> 

SEC("cgroup_skb/egress")
int drop_unwanted_dns_queries(struct __sk_buff *skb) {
    struct iphdr ip;

    /* Load the IP header from the packet buffer */
    /* skb->data is at the Network Layer (L3) for cgroup_skb */
    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0) {
        return 1; // Let non-IP traffic pass
    }

    /* Logic: Drop traffic to 1.1.1.1 (0x01010101 in hex) */
    /* Note: IP addresses are in Network Byte Order (Big Endian) */
    if (ip.daddr == 0x01010101) {
        return 0; // 0 = DROP the packet
    }

    return 1; // 1 = PASS the packet
}

char _license[] SEC("license") = "GPL";




