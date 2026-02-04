
from firewall import BPFFirewall
from bpfmanager import BPFManager 

def main(): 

    bpf_manager = BPFManager(so_file="./libguard.so", ip_map="blkd_ip_map", domain_map="blkd_domain_map", query_rb="query_events")

    firewall = BPFFirewall(bpf_manager)

    bpf_manager.set_ringbuffer_callback(lambda: print("hi from python"))
    bpf_manager.poll_ringbuffer()


if __name__ == "__main__": 
    main()



