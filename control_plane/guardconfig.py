
from firewall import Firewall, BPFFirewall, CSVFirewall
from recordreceiver import RecordReceiver, BPFRecordReceiver, CSVRecordReceiver
from bpfmanager import BPFManager 

from configparser import ConfigParser
from dataclasses import dataclass

def parse_guard_types(args, config: ConfigParser) -> tuple[RecordReceiver, Firewall]: 

    resources = GuardResources(bpf_manager=None, firewall_csv_path=None, receiver_csv_path=None)

    resources.firewall_csv_path = args.csv_firewall_path

    resources.receiver_csv_path = args.csv_records_path

    return parse_record_receiver(config, resources), parse_firewall(config, resources) 


# -------------- Private

@dataclass
class GuardResources: 
    bpf_manager: BPFManager | None
    firewall_csv_path: str | None
    receiver_csv_path: str | None
    

def parse_ebpf_config(config: ConfigParser) -> BPFManager: 
    ebpf_config = config['ebpf']
    return BPFManager(so_file=ebpf_config['so_file'], 
                     ip_map=ebpf_config['ip_map'], 
                     domain_map=ebpf_config['domain_map'],
                     query_rb=ebpf_config['query_rb'])


def parse_firewall(config: ConfigParser, resources: GuardResources) -> Firewall: 
    firewall_type = config['firewall']['type']
    if firewall_type  == 'ebpf': 
        if resources.bpf_manager is None: 
            resources.bpf_manager = parse_ebpf_config(config)
        return BPFFirewall(resources.bpf_manager)
    elif firewall_type == 'csv': 
        if resources.firewall_csv_path is None: 
            resources.firewall_csv_path = 'blocked.csv'
        return CSVFirewall(resources.firewall_csv_path)
    else: 
        raise Exception(f"Invalid firewall type {firewall_type}")


def parse_record_receiver(config: ConfigParser, resources: GuardResources) -> RecordReceiver: 
    receiver_type = config['recordreceiver']['type']
    if receiver_type == 'ebpf': 
        if resources.bpf_manager is None: 
            resources.bpf_manager = parse_ebpf_config(config)
        return BPFRecordReceiver(resources.bpf_manager)

    elif receiver_type == 'csv': 
        if resources.receiver_csv_path is None: 
            raise Exception("Path to CSV DNS Records not provided")
        return CSVRecordReceiver(resources.receiver_csv_path)
    else: 
        raise Exception(f"Invalid Record Receiver type: {receiver_type}")


