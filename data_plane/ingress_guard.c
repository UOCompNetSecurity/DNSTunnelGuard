
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

#define MAX_BLOCKED_LENGTH 10000
#define MAX_IP_MAPPINGS 1000
#define MAX_IPS_PER_QUERY 1000
#define MAX_QNAME_SIZE 255
#define DROP 0
#define PASS 1

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);  // IP addr
    __type(value, uint8_t); // is blocked
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} ingress_ip_map SEC(".maps");

// Map query name to IP addresses

typedef struct
{
    uint32_t ip_addresses[MAX_IPS_PER_QUERY]; 
    uint32_t num_ip_addresses; 

} IPAddresses;

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_QNAME_SIZE]);
    __type(value, IPAddresses);
    __uint(max_entries, MAX_IP_MAPPINGS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} query_to_ip;

SEC("cgroup_skb/ingress")
int check_tunnel(struct __sk_buff* skb)
{
    struct iphdr ip;

    if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)) < 0)
        return PASS;




    return PASS;
}

char _license[] SEC("license") = "GPL";
















