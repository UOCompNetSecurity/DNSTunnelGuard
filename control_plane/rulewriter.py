
import csv 
import ctypes
import socket 
import struct 
import os 


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
        raise NotImplementedError("block_src_ip_address not implemented")

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

    def __init__(self, so_file: str, ip_map: str, domain_map: str): 
        self.bpf = ctypes.CDLL(so_file)

        self.bpf.get_map_fd.argtypes = [ctypes.c_char_p]

        # IP map 
        self.bpf.map_ip.argtypes       = [ctypes.c_int, ctypes.c_uint32]
        self.bpf.unmap_ip.argtypes     = [ctypes.c_int, ctypes.c_uint32]
        self.bpf.map_domain.argtypes   = [ctypes.c_int, ctypes.c_char_p]
        self.bpf.unmap_domain.argtypes = [ctypes.c_int, ctypes.c_char_p]

        self.ip_map = ip_map
        self.domain_map = domain_map
        self.blocked_ip_map_fd = -1
        self.blocked_domain_map_fd = -1

    # No need to call these when using "with" context management
    def open_maps(self): 
        self.blocked_ip_map_fd = self.bpf.get_map_fd(self.ip_map.encode("utf-8"))
        if self.blocked_ip_map_fd < 0: 
            raise Exception(f"Could not find file descriptor for map {self.ip_map}")

        self.blocked_domain_map_fd = self.bpf.get_map_fd(self.domain_map.encode("utf-8"))
        if self.blocked_domain_map_fd < 0: 
            raise Exception(f"Could not find file descriptor for map {self.domain_map}")

    def close_maps(self): 
        if self.blocked_ip_map_fd != -1: 
            os.close(self.blocked_ip_map_fd)
        if self.blocked_domain_map_fd != -1: 
            os.close(self.blocked_domain_map_fd)


    def __enter__(self): 
        self.open_maps()
        return self 

    def __exit__(self, exc_type, exc_value, traceback): 
        self.close_maps()
        return False

    def block_ip_address(self, ip_address: str): 
        self._block_ip(self.blocked_ip_map_fd, ip_address)

    def unblock_ip_address(self, ip_address: str): 
        self._unblock_ip(self.blocked_ip_map_fd, ip_address)

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






























