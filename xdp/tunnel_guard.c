

#include <linux/bpf.h> 
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>


SEC("xdp_drop")
int xdp_drop_prog(struct xdp_md* ctx)
{
    void* data_end = (void*)(long)ctx->data_end; 
    void* data = (void*)(long)ctx->data; 

    // Ethernet 

    data += sizeof(struct ethhdr);
    if (data > data_end)
    {
        return XDP_DROP; 
    }






    return XDP_PASS;
}



char _license[] SEC("license") = "GPL";
