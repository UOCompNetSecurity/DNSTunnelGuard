
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)

#define MAX_BLOCKED_LENGTH 10000
#define DROP 0
#define PASS 1

// DNS
#define DNS_HDR_LEN 12
#define MAX_QNAME_LEN 50
#define MAX_LABEL_SIZE 63
#define DNS_PORT 53

#define QTYPE_A 1
#define QTYPE_AAAA 28
#define QTYPE_NS 2
#define QTYPE_SOA 6
#define QTYPE_MX 15
#define QTYPE_PTR 12
#define QTYPE_CNAME 5

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);  // IP addr
    __type(value, uint8_t); // is blocked
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} dst_ip_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_QNAME_LEN]); // Domain Name
    __type(value, uint8_t);           // is blocked
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} domain_map SEC(".maps");

SEC("cgroup_skb/egress")
int check_tunnel(struct __sk_buff* skb)
{
    void* data_end = (void*)(long)skb->data_end;
    void* data     = (void*)(long)skb->data;


    if ((void*)(data + sizeof(struct iphdr)) >= data_end)
        return PASS;

    /* ------------------------------ IP ---------------------------- */ 

    // TODO handle IPV6
    struct iphdr* ip_header = data;

    uint32_t ip_big_d = bpf_htonl(ip_header->daddr);

    uint8_t* is_ip_blocked = bpf_map_lookup_elem(&dst_ip_map, &ip_big_d);

    if (is_ip_blocked)
        return DROP;

    /* ---------------------------- Transport ---------------------------- */ 

    uint16_t dst_port;
    void* dns_header;

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = (void*)ip_header + (ip_header->ihl * 4);
        if ((void*)udp_header + sizeof(struct udphdr) >= data_end)
            return PASS;
        dst_port   = udp_header->dest;
        dns_header = (void*)udp_header + sizeof(struct udphdr);
    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcp_header = (void*)ip_header + (ip_header->ihl * 4);
        if ((void*)tcp_header + sizeof(struct tcphdr) >= data_end)
            return PASS;
        dst_port   = tcp_header->dest;
        dns_header = (void*)tcp_header + sizeof(struct tcphdr);
    }
    else
    {
        return PASS;
    }

    /* ----------------------------  DNS ---------------------------- */ 

    // This is egress traffic, we only need to analyze queries going to DNS servers, 
    // not traffic being sent back to the client
    
    // if (dst_port != DNS_PORT)
    //     return PASS; 

    if (dns_header >= data_end)
        return PASS;

    char* qname = dns_header + DNS_HDR_LEN;

    if ((void*)qname >= data_end)
        return PASS;

    char domain_buffer[MAX_QNAME_LEN];
    int  label_chars = 0;


    int byte_num;
    #pragma unroll
    for (byte_num = 0; byte_num < MAX_QNAME_LEN; byte_num++)
    {
        if ((void*)&qname[byte_num] >= data_end || label_chars > MAX_LABEL_SIZE)
            return DROP;

        if (qname[byte_num] == '\0')
        {
            domain_buffer[byte_num] = '\0';
            break;
        }

        if (label_chars == 0)
        {
            domain_buffer[byte_num] = '.';
            label_chars = qname[byte_num];
        }
        else
        {
            domain_buffer[byte_num] = qname[byte_num];
            label_chars--;
        }
    }

    // No terminater byte found
    if (domain_buffer[byte_num] != '\0')
        return DROP; 

    
    // Check each sub domain to see if it is blocked
    #pragma unroll
    for (int i = 0; i < MAX_QNAME_LEN; i++)
    {
        if (domain_buffer[i] == '.')
        {
            char* sub_domain = domain_buffer + i + 1; 
            uint8_t* is_blocked = bpf_map_lookup_elem(&domain_map, &domain_buffer);
        }
    }

    uint16_t* qtype_ptr = (uint16_t*)(qname + byte_num + 1);

    if ((char*)(qtype_ptr + 1) > (char*)data_end)
        return DROP;

    //
    // uint16_t qtype = bpf_ntohs(*qtype_ptr);
    //
    // // Drop queries of unnallowed query types
    // switch (qtype)
    // {
    // case QTYPE_A:
    // case QTYPE_AAAA:
    // case QTYPE_CNAME:
    // case QTYPE_MX:
    // case QTYPE_NS:
    // case QTYPE_SOA:
    // case QTYPE_PTR:
    //     // TODO: push packet to control plane
    //     return PASS;
    //
    // default: 
    //     return DROP;
    // }
    //

    return PASS;
}

char _license[] SEC("license") = "GPL";
