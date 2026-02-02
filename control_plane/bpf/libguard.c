


#include <arpa/inet.h> 
#include <string.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h> 
#include <stdlib.h> 

#define MAX_QNAME_LEN 32

int get_map_fd(const char* name)
{
    int map_fd = -1; 
    __u32 id = 0; 
    while (bpf_map_get_next_id(id, &id) == 0)
    {
        struct bpf_map_info info = {};
        __u32 info_len = sizeof(info);
        int fd;

        fd = bpf_map_get_fd_by_id(id);
        if (fd < 0) continue;

        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) 
        {
            if (strcmp(info.name, name) == 0) 
            {
                map_fd = fd;
                break;
            }
        }
        close(fd);
    }
    return map_fd; 
}


int map_ip(int fd, uint32_t ip_addr)
{
    int blocked = 1;
    return bpf_map_update_elem(fd, &ip_addr, &blocked, BPF_ANY);
}

int unmap_ip(int fd, uint32_t ip_addr)
{
    return bpf_map_delete_elem(fd, &ip_addr);
}

int map_domain(int fd, char* domain_name)
{
    char key[MAX_QNAME_LEN] = {0};  
    strncpy(key, domain_name, MAX_QNAME_LEN);
    uint8_t blocked = 1;

    return bpf_map_update_elem(fd, key, &blocked, BPF_ANY);
}

int unmap_domain(int fd, char* domain)
{
    char key[MAX_QNAME_LEN] = {0};  
    strncpy(key, domain, MAX_QNAME_LEN);
    return bpf_map_delete_elem(fd, key);
}












