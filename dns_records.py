
import datetime 


class DNSRecords: 
    """
    DNSRecords stores banned domain names and IP addresses. 
    Derived classes must implement the storing of the records 

    """
    def __init__(self, max_size=None): 
        self.domains: set[tuple[str, datetime.datetime]] = set()
        self.ip_addresses: set[tuple[str, datetime.datetime]] = set()
        self.max_size = max_size

    def add_domain(self, domain: str): 
        self.domains.add((domain, datetime.datetime.now()))
        self._add_domain(domain)

    def add_ip_address(self, ip_addr: str): 
        self.ip_addresses.add((ip_addr, datetime.datetime.now()))
        self._add_ip_address(ip_addr)


    def _add_domain(self, domain: str): 
        """
        Implemented in derived class if domain needs to be added somewhere else beyond program memory
        """
        pass 

    def _add_ip_address(self, ip_addr: str): 
        """
        Implemented in derived class if ip address needs to be added somewhere else beyond program memory
        """
        pass 




















