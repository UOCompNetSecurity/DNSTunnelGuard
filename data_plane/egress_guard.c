

#include "guards.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_QNAME_LEN]); // Domain Name
    __type(value, uint8_t);           // is blocked
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} blkd_domain_map SEC(".maps");

/* Buffer to write DNS queries for further inspection in user space */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} query_events SEC(".maps");

struct query_event
{
    uint32_t ip_address; 
    char     query_data[MAX_QUERY_LEN];
};

/* Tunnel guard for outgoing traffic (egress) from the DNS resolver
 *
 * Inspects DNS queries being sent from the resolver to other DNS servers so that only uncached
 * queries are checked
 *
 * Drops the DNS query if the qname is blocked
 *
 * Only handles IPv4 at this time
 *
 * Does not block based on IP address, that is left to the incoming traffic guard (ingress)
 *
 */

SEC("cgroup_skb/egress")
int tunnel_guard_egress(struct __sk_buff* skb)
{
    void* data_end = (void*)(long)skb->data_end;
    void* data     = (void*)(long)skb->data;

    /* ------------------------------ IP ---------------------------- */

    /* No ipv6, too complicated to parse rn */

    if (skb->protocol == bpf_htons(ETH_P_IPV6))
        return DROP;

    if (data + sizeof(struct iphdr) >= data_end)
        return PASS;

    struct iphdr* ip_header = data;

    /* ---------------------------- Transport ---------------------------- */

    uint16_t dst_port;
    void*    dns_header;
    void*    transport_header = (void*)ip_header + ip_header->ihl * 4;

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = transport_header;
        if ((void*)udp_header + sizeof(struct udphdr) >= data_end)
            return PASS;
        dst_port   = udp_header->dest;
        dns_header = (void*)udp_header + sizeof(struct udphdr);
    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        return DROP; // I dont want to deal with tcp rn 
    }
    else
    {
        return PASS;
    }

    if (dns_header >= data_end)
        return PASS;

    /* ----------------------------  DNS ---------------------------- */

    /*
     * This is egress traffic, we only need to analyze queries going to DNS servers,
     * not traffic being sent back to the client
     */

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

    /* Get the requsters IP address with this query */

    char full_qname[MAX_QNAME_LEN] = {0};

    if (bpf_probe_read_kernel(full_qname, len, qname) < 0)
        return DROP;

    uint32_t* ip_addr_p = bpf_map_lookup_elem(&query_to_ip, full_qname);

    if (!ip_addr_p)
        return DROP;

    uint32_t ip_addr = bpf_htonl(*ip_addr_p);

    bpf_map_delete_elem(&query_to_ip, full_qname);

    /*
     * Check each subdomain and drop if it is blocked
     * EX: JFDSL.attacker.com
     * Checks JFDSL.attacker.com
     * Then checks attacker.com
     * Then .com
     * Checks in wire format, not presentation
     */

    int remaining_label_chars = 0;
    for (int i = 0; i < len; i++)
    {
        if (remaining_label_chars == 0)
        {
            char sub_domain[MAX_QNAME_LEN] = {0};

            int copy_len = len - i + 1;

            if (bpf_probe_read_kernel(sub_domain, copy_len, qname + i) < 0)
                return DROP;

            if (bpf_map_lookup_elem(&blkd_domain_map, sub_domain))
                return DROP;

            remaining_label_chars = qname[i];
        }
        else
        {
            remaining_label_chars--;
        }
    }

    /* Filter by QTYPE */

    uint16_t* qtype_ptr = (uint16_t*)(qname + len + 1);

    if ((char*)(qtype_ptr + 1) > (char*)data_end)
        return DROP;

    uint16_t qtype = bpf_ntohs(*qtype_ptr);

    /* Drop queries of unnallowed query types */
    switch (qtype)
    {
    case QTYPE_A:
    case QTYPE_AAAA:
    case QTYPE_CNAME:
    case QTYPE_MX:
    case QTYPE_NS:
    case QTYPE_SOA:
    case QTYPE_PTR:
    {
        /* Pass query to userspace for further inspection */ 

        struct query_event* event = bpf_ringbuf_reserve(&query_events, sizeof(struct query_event), 0); 

        if (!event)
            return DROP; 

        event->ip_address = bpf_ntohl(ip_addr); 
        for (int i = 0; i < MAX_QUERY_LEN; i++)
        {
            if (dns_header + i >= data_end)
                break;

            event->query_data[i] = ((char*)dns_header)[i];
        }
        bpf_ringbuf_submit(event, 0);

        return PASS;
    }

    default:
        return DROP;
    }

    return PASS;
}

char _license[] SEC("license") = "GPL";
