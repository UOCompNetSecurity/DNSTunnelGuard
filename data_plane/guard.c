
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

#define MAX_BLOCKED_LENGTH 10000
#define DROP 0
#define PASS 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);  // IP addr
    __type(value, uint8_t); // is blocked
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} ip_block_map SEC(".maps");



SEC("cgroup_skb/egress")
int check_tunnel(struct __sk_buff* skb)
{
    struct iphdr ip;

    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
        return PASS;

    uint32_t ip_big_d = bpf_htonl(ip.daddr);
    
    uint8_t* is_ip_blocked = bpf_map_lookup_elem(&ip_block_map, &ip_big_d);

    if (is_ip_blocked)
    {
        return DROP; 
    }

    return PASS;
}

char _license[] SEC("license") = "GPL";



