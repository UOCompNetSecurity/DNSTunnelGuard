
import csv 
import ctypes
import socket 
import struct 
import os 


class RuleWriter: 
    """
    Abstract class for writing 

    """

    def __enter__(self): 
        raise NotImplementedError("__enter__ not implemented")

    def __exit__(self, exc_type, exc_value, traceback): 
        raise NotImplementedError("__exit__ not implemented")

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

    def close(self): 
        self._csv_file.close()

    def __enter__(self): 
        self.open()
        return self

    def __exit__(self, exc_type, exc_value, traceback): 
        self.close()
        return False

    def block_domain(self, domain: str): 
        self._csv_writer.writerow([domain, ""])

    def block_ip_address(self, ip_address: str): 
        self._csv_writer.writerow(["", ip_address])

class BPFRuleWriter(RuleWriter): 

    bpf: ctypes.CDLL | None = None

    def __init__(self, so_file: str, ip_map: str): 
        if BPFRuleWriter.bpf is None: 
            BPFRuleWriter.bpf = ctypes.CDLL(so_file)

        self.bpf = BPFRuleWriter.bpf

        self.bpf.get_map_fd.argtypes = [ctypes.c_char_p]

        # IP map 
        self.bpf.map_ip.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_uint8]
        self.bpf.unmap_ip.argtypes = [ctypes.c_int, ctypes.c_uint32]

        self.ip_map = ip_map
        self.blocked_ip_map_fd = -1

    # No need to call these when using "with" context management
    def open_maps(self): 
        if self.bpf is None: 
            raise Exception("No SO loaded")

        self.blocked_ip_map_fd = self.bpf.get_map_fd(self.ip_map.encode("utf-8"))
        if self.blocked_ip_map_fd < 0: 
            raise Exception(f"Could not find file descriptor for map {self.ip_map}")

    def close_maps(self): 
        if self.blocked_ip_map_fd != -1: 
            os.close(self.blocked_ip_map_fd)

    def __enter__(self): 
        self.open_maps()
        return self 

    def __exit__(self, exc_type, exc_value, traceback): 
        self.close_maps()
        return False

    def block_domain(self, domain: str): 
        pass

    def block_ip_address(self, ip_address: str): 
        self._block_ip(self.blocked_ip_map_fd, ip_address)

    def unblock_ip_address(self, ip_address: str): 
        self._unblock_ip(self.blocked_ip_map_fd, ip_address)

    def _block_ip(self, fd: int, ip_address: str): 
        if self.bpf is None: 
            raise Exception("No SO loaded")
        res = self.bpf.map_ip(fd, self._ip_to_int(ip_address), 1)
        if res < 0: 
            raise Exception(f"Failed to block IP address {ip_address}")

    def _unblock_ip(self, fd: int, ip_address): 
        if self.bpf is None: 
            raise Exception("No SO loaded")

        res = self.bpf.unmap_ip(fd, self._ip_to_int(ip_address))
        if res < 0: 
            raise Exception(f"Failed to unblock IP address {ip_address}")

    def _ip_to_int(self, ip_addr: str) -> bytes: 
        ip_bytes = socket.inet_pton(socket.AF_INET, ip_addr)
        return struct.unpack("!I", ip_bytes)[0]






























