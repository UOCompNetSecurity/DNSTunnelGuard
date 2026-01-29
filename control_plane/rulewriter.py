
import csv 
import ctypes
import socket 
import struct 
import os 


class RuleWriter: 
    """
    Abstract class for writing 

    """

    def block_domain(self, domain: str): 
        raise NotImplementedError("block_domain not implemented")

    def block_src_ip_address(self, ip_address: str): 
        raise NotImplementedError("block_src_ip_address not implemented")

    def block_dst_ip_address(self, ip_address: str): 
        raise NotImplementedError("block_dst_ip_address not implemented")

class CSVRuleWriter(RuleWriter): 

    def __init__(self, path: str): 
        self._path = path
        self._csvfile = None
        self._csv_writer = None

    # No 
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

    def block_src_ip_address(self, ip_address: str): 
        if self._csv_writer is not None: 
            self._csv_writer.writerow(["", ip_address, ""])

    def block_dst_ip_address(self, ip_address: str): 
        if self._csv_writer is not None: 
            self._csv_writer.writerow(["", "", ip_address])


class BPFRuleWriter(RuleWriter): 

    bpf: ctypes.CDLL | None = None

    def __init__(self, so_file: str, src_ip_map: None | str=None, dst_ip_map: None | str=None, domain_map: None | str=None): 

        if BPFRuleWriter.bpf is None: 
            BPFRuleWriter.bpf = ctypes.CDLL(so_file)

        self.bpf = BPFRuleWriter.bpf

        self.bpf.get_map_fd.argtypes = [ctypes.c_char_p]

        # IP map 
        self.bpf.map_ip.argtypes       = [ctypes.c_int, ctypes.c_uint32]
        self.bpf.unmap_ip.argtypes     = [ctypes.c_int, ctypes.c_uint32]
        self.bpf.map_domain.argtypes   = [ctypes.c_int, ctypes.c_char_p]
        self.bpf.unmap_domain.argtypes = [ctypes.c_int, ctypes.c_char_p]

        self.src_ip_map = src_ip_map 
        self.dst_ip_map = dst_ip_map
        self.domain_map = domain_map
        self.blocked_src_ip_map_fd = -1
        self.blocked_dst_ip_map_fd = -1
        self.blocked_domain_map_fd = -1

    # No need to call these when using "with" context management
    def open_maps(self): 
        if self.bpf is None: 
            raise Exception("No SO loaded")

        if self.src_ip_map is not None: 
            self.blocked_src_ip_map_fd = self.bpf.get_map_fd(self.src_ip_map.encode("utf-8"))
            if self.blocked_src_ip_map_fd < 0: 
                raise Exception(f"Could not find file descriptor for map {self.src_ip_map}")

        if self.dst_ip_map is not None: 
            self.blocked_dst_ip_map_fd = self.bpf.get_map_fd(self.dst_ip_map.encode("utf-8"))
            if self.blocked_src_ip_map_fd < 0: 
                raise Exception(f"Could not find file descriptor for map {self.dst_ip_map}")

        if self.domain_map is not None: 
            self.blocked_domain_map_fd = self.bpf.get_map_fd(self.domain_map.encode("utf-8"))
            if self.blocked_domain_map_fd < 0: 
                raise Exception(f"Could not find file descriptor for map {self.blocked_domain_map_fd}")

    def close_maps(self): 
        if self.blocked_src_ip_map_fd != -1: 
            os.close(self.blocked_src_ip_map_fd)
        if self.blocked_dst_ip_map_fd != -1: 
            os.close(self.blocked_dst_ip_map_fd)

    def __enter__(self): 
        self.open_maps()
        return self 

    def __exit__(self, exc_type, exc_value, traceback): 
        self.close_maps()
        return False

    def block_src_ip_address(self, ip_address: str): 
        if self.src_ip_map is None: 
            raise Exception("Could not block source IP address, source map ip not set")
        self._block_ip(self.blocked_src_ip_map_fd, ip_address)

    def block_dst_ip_address(self, ip_address: str): 
        if self.dst_ip_map is None: 
            raise Exception("Could not block destination IP address, source map ip not set")
        self._block_ip(self.blocked_dst_ip_map_fd, ip_address)

    def unblock_src_ip_address(self, ip_address: str): 
        if self.src_ip_map is None: 
            raise Exception("Could not unblock source IP address, source map ip not set")
        self._unblock_ip(self.blocked_src_ip_map_fd, ip_address)

    def unblock_dst_ip_address(self, ip_address: str): 
        if self.dst_ip_map is None: 
            raise Exception("Could not unblock destination IP address, source map ip not set")
        self._unblock_ip(self.blocked_dst_ip_map_fd, ip_address)

    def block_domain(self, domain: str): 
        if self.domain_map is None: 
            raise Exception("Could not block domain, source map ip not set")
        if self.bpf is None: 
            raise Exception("No SO loaded")
        res = self.bpf.map_domain(self.blocked_domain_map_fd, domain.encode("utf-8"))
        if res < 0: 
            raise Exception(f"Failed to block domain {domain}")

    def unblock_domain(self, domain: str): 
        if self.domain_map is None: 
            raise Exception("Could not unblock domain, source map ip not set")
        if self.bpf is None: 
            raise Exception("No SO loaded")
        res = self.bpf.unmap_domain(self.blocked_domain_map_fd, domain.encode("utf-8"))
        if res < 0: 
            raise Exception(f"Failed to block domain {domain}")

    def _block_ip(self, fd: int, ip_address: str): 
        if self.bpf is None: 
            raise Exception("No SO loaded")
        res = self.bpf.map_ip(fd, self._ip_to_int(ip_address))
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

































