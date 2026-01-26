
import csv 
import ctypes
import socket 
import struct 


class RuleWriter: 
    """
    Abstract class for writing 

    """

    def block_domain(self, domain: str): 
        raise NotImplementedError("block_domain not implemented")

    def block_ip_address(self, ip_address: str): 
        raise NotImplementedError("block_ip_address not implemented")


class CSVRuleWriter(RuleWriter): 

    def __init__(self, path: str): 
        self._csv_file = open(path, "w")
        self._csv_writer = csv.writer(self._csv_file)
        self._csv_writer.writerow(["domain", "ip address"])

    def __del__(self):
        if hasattr(self, "_csv_file") and not self._csv_file.closed:
            self._csv_file.close()

    def block_domain(self, domain: str): 
        self._csv_writer.writerow([domain, ""])

    def block_ip_address(self, ip_address: str): 
        self._csv_writer.writerow(["", ip_address])


class BPFRuleWriter(RuleWriter): 

    def __init__(self, so_file_path: str, blocked_ip_map_name: str): 
        self.bpf = ctypes.CDLL(so_file_path)

        self.bpf.get_map_fd.argtypes = [ctypes.c_char_p]

        # IP map 
        self.bpf.map_ip.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_uint8]
        self.bpf.unmap_ip.argtypes = [ctypes.c_int, ctypes.c_uint32]
        self.blocked_ip_map_fd = self.bpf.get_map_fd(blocked_ip_map_name.encode("utf-8"))
        if self.blocked_ip_map_fd < 0: 
            raise Exception(f"Could not find FD for map {blocked_ip_map_name}")


    def block_domain(self, domain: str): 
        pass

    def block_ip_address(self, ip_address: str): 
        res = self.bpf.map_ip(self.blocked_ip_map_fd, self._ip_to_int(ip_address), 1)
        if res < 0: 
            raise Exception(f"Failed to block IP address {ip_address}")

    def unblock_ip_address(self, ip_address: str): 
        res = self.bpf.unmap_ip(self.blocked_ip_map_fd, self._ip_to_int(ip_address))
        if res < 0: 
            raise Exception(f"Failed to unblock IP address {ip_address}")

    def _ip_to_int(self, ip_addr: str) -> bytes: 
        ip_bytes = socket.inet_pton(socket.AF_INET, ip_addr)
        return struct.unpack("!I", ip_bytes)[0]































