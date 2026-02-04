
import ctypes
import struct 
import socket 


class BPFManager: 

    def __init__(self, so_file: str, ip_map: str, domain_map: str, query_rb: str): 
        self.bpf = ctypes.CDLL(so_file)

        self.bpf.get_map_fd.argtypes = [ctypes.c_char_p]

        self._ip_map_fd = self.bpf.get_map_fd(ip_map.encode())
        if self._ip_map_fd < 0: 
            raise Exception(f"Could not find IP map {ip_map}")

        self._domain_map_fd = self.bpf.get_map_fd(domain_map.encode())
        if self._domain_map_fd < 0: 
            raise Exception(f"Could not find domain map {domain_map}")

        self._ringbuffer_fd = self.bpf.get_map_fd(query_rb.encode()) 
        if self._ringbuffer_fd < 0: 
            raise Exception(f"Could not find ringbuffer {query_rb}")


    def map_ip(self, ip: str): 
        if self.bpf.map_ip(self._ip_map_fd, self._ip_to_wire(ip)) < 0: 
            raise Exception("Could not map IP")

    def unmap_ip(self, ip: str): 
        if self.bpf.unmap_ip(self._ip_map_fd, self._ip_to_wire(ip)) < 0: 
            raise Exception("Could not unmap IP")

    def map_domain(self, domain: str): 
        if self.bpf.map_domain(self._domain_map_fd, self._domain_to_wire(domain)) < 0: 
            raise Exception("Could not map domain")

    def unmap_domain(self, domain: str): 
        if self.bpf.unmap_domain(self._domain_map_fd, self._domain_to_wire(domain)) < 0: 
            raise Exception("Could not unmap domain")

    def set_ringbuffer_callback(self, callback): 

        @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)
        def rb_callback(ctx, data, size): 
            callback()
            return 0

        self._saved_callback = rb_callback # Prevent garbage collection 

        if self.bpf.create_ringbuffer(self._ringbuffer_fd, self._saved_callback) < 0: 
            raise Exception("Could not create ring buffer")

    def poll_ringbuffer(self, timeout: int): 
            self.bpf.poll_ringbuffer(self._ringbuffer_fd, timeout)

    def _ip_to_wire(self, ip_addr: str): 
        ip_bytes = socket.inet_pton(socket.AF_INET, ip_addr)
        return struct.unpack("I", ip_bytes)[0]

    def _domain_to_wire(self, domain: str) -> bytes: 
        domains = domain.split('.')

        wire_domain = b""

        for d in domains: 
            wire_domain += len(d).to_bytes(1)
            wire_domain += d.encode("utf-8")

        wire_domain += b"\x00"
        return wire_domain











































    













