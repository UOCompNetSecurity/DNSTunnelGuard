
from firewall import BPFFirewall
from recordreceiver import BPFRecordReceiver
from bpfmanager import BPFManager 

def main(): 

    bpf_manager = BPFManager(so_file="./libguard.so", 
                             ip_map="blkd_ip_map", 
                             domain_map="blkd_domain_map",
                             query_rb="query_events")

    record_receiver = BPFRecordReceiver(bpf_manager, lambda record: print(record))

    with record_receiver: 
        record_receiver.receive()


if __name__ == "__main__": 
    main()



