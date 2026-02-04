
#include "guards.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);  // IP address 
    __type(value, uint8_t); // is blocked 
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blkd_ip_map SEC(".maps");


/* Tunnel guard for incoming traffic (ingress) to the DNS resolver
 *
 * Drops packets if the requesters IP addrss is blocked
 *
 * Inspects DNS queries being sent to the resolver from requesters 
 * Maps their IP address to a unique key using the qname + query ID 
 * 
 */
SEC("cgroup_skb/ingress")
int tunnel_guard_ingress(struct __sk_buff* skb)
{

    void* data_end = (void*)(long)skb->data_end;
    void* data     = (void*)(long)skb->data;

    /* No ipv6, too complicated to parse rn */

    if (skb->protocol == bpf_htons(ETH_P_IPV6))
        return DROP;

    if (data + sizeof(struct iphdr) >= data_end)
        return PASS;

    struct iphdr* ip_header = data;

    /* Drop query if the packet comes from a blocked requesters IP */ 
    if (bpf_map_lookup_elem(&blkd_ip_map, &ip_header->saddr))
        return DROP; 

    void*    transport_header = (void*)ip_header + ip_header->ihl * 4;
    void*    dns_header;
    uint16_t dst_port;

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = transport_header;
        if ((void*)udp_header + sizeof(struct udphdr) >= data_end)
            return PASS;
        dns_header = (void*)udp_header + sizeof(struct udphdr);
        dst_port   = udp_header->dest; 
    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp_header = transport_header;
        if ((void*)tcp_header + sizeof(struct tcphdr) >= data_end)
            return PASS;
        dns_header = (void*)tcp_header + sizeof(struct tcphdr);
        dst_port   = tcp_header->dest; 
    }
    else
    {
        return PASS;
    }

    if (dns_header >= data_end)
        return PASS;

    /* Only look at traffic coming from user queries */ 
    if (bpf_ntohs(dst_port) != DNS_PORT)
        return PASS;

    char* qname = dns_header + DNS_HDR_LEN;

    /* Determine the length and drop if too long*/
    int len;
    for (len = 0; len < MAX_QNAME_LEN; len++)
    {
        if ((void*)qname + len >= data_end)
            return DROP;

        if (qname[len] == '\0')
            break;
    }

    if (len > MAX_QNAME_LEN)
        return DROP;

    char full_qname[MAX_QNAME_LEN] = {0};

    if (bpf_probe_read_kernel(full_qname, len, qname) < 0)
        return DROP;

    bpf_map_update_elem(&query_to_ip, full_qname, &ip_header->saddr, BPF_ANY);
    
    return PASS; 
}

char _license[] SEC("license") = "GPL";





