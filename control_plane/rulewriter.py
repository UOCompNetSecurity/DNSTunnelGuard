
import csv 
import ctypes
import socket 
import struct 
import os 
from bcc import BPF

class RuleWriter: 
    """
    Abstract class for writing 

    """

    def __open__(self): 
        return self

    def __exit__(self, exc_type, exc_value, traceback): 
        return False

    def block_domain(self, domain: str): 
        raise NotImplementedError("block_domain not implemented")

    def block_ip_address(self, ip_address: str): 
        raise NotImplementedError("block_ip_address not implemented")

class CSVRuleWriter(RuleWriter): 

    def __init__(self, path: str): 
        self._path = path
        self._csv_file = open(self._path, "w")
        self._csv_writer = csv.writer(self._csv_file)
        self._csv_writer.writerow(["domain", "ip address"])
        self._csv_file.close()

    def open(self): 
        self._csv_file = open(self._path, "w")
        self._csv_writer = csv.writer(self._csv_file)
        self._csv_writer.writerow(["domain", "src ip address", "dst ip address"])

    def close(self): 
        if self._csv_file is not None: 
            self._csv_file.close()

    def __enter__(self): 
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback): 
        self.close()
        return False

    def block_domain(self, domain: str): 
        if self._csv_writer is not None: 
            self._csv_writer.writerow([domain, ""])

    def block_ip_address(self, ip_address: str): 
        self._csv_writer.writerow(["", ip_address])


class BPFRuleWriter(RuleWriter): 
    # TODO: finish this 

    def __init__(self, bpf_file: str, cgroup_path: str): 

        bpf = BPF(file=bpf_file)

        ingress_fn = bpf.load_func("tunnel_guard_ingress", BPF.CGROUP_SKB)
        egress_fn = bpf.load_func("tunnel_guard_engress", BPF.CGROUP_SKB)

        fd = os.open(cgroup_path, os.O_RDONLY)

        bpf.attach_bgroup(BPF.BPF_CGROUP_INET_INGRESS, fd, obj=ingress_fn)
        bpf.attach_bgroup(BPF.BPF_CGROUP_INET_EGRESS, fd, obj=egress_fn)

        self.blocked_domain_map = bpf["blkd_domain_map"]
        self.blocked_ip_map = bpf["blkd_ip_map"]
        self.query_ringbuffer = bpf["query_events"]

    def block_ip_address(self, ip_address: str): 
        key = self.blocked_ip_map.Key(self._ip_to_int(ip_address))
        value = self.blocked_ip_map.Leaf(1)
        self.blocked_ip_map[key] = value

    def unblock_ip_address(self, ip_address: str): 
        key = self.blocked_ip_map.Key(self._ip_to_int(ip_address))
        del self.blocked_ip_map[key]

    def block_domain(self, domain: str): 
        if self.bpf.map_domain(self.blocked_domain_map_fd, self._domain_to_wire(domain)) < 0: 
            raise Exception(f"Failed to block domain {domain}")

    def unblock_domain(self, domain: str): 
        if self.bpf.unmap_domain(self.blocked_domain_map_fd, self._domain_to_wire(domain)) < 0: 
            raise Exception(f"Failed to block domain {domain}")

    def _block_ip(self, fd: int, ip_address: str): 
        
        if self.bpf.map_ip(fd, self._ip_to_int(ip_address)) < 0: 
            raise Exception(f"Failed to block IP address {ip_address}")

    def _unblock_ip(self, fd: int, ip_address): 
        if self.bpf.unmap_ip(fd, self._ip_to_int(ip_address)) < 0: 
            raise Exception(f"Failed to unblock IP address {ip_address}")

    def _ip_to_int(self, ip_addr: str) -> bytes: 
        ip_bytes = socket.inet_pton(socket.AF_INET, ip_addr)
        return struct.unpack("!I", ip_bytes)[0]

    def _domain_to_wire(self, domain: str) -> bytes: 
        domains = domain.split('.')

        wire_domain = b""

        for d in domains: 
            wire_domain += len(d).to_bytes(1)
            wire_domain += d.encode("utf-8")

        wire_domain += b"\x00"
        return wire_domain






























