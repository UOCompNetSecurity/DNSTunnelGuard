
import struct
import socket 

def parse_qname_no_tld(qname: str) -> list[str]: 
    """
    Splits a qname into parts, excludes the top level domain 
    """
    if not qname: 
        return []
    domains = qname.split('.')

    split = [".".join(domains[i:]) for i in range(len(domains)) if domains[i]]

    split.pop() # pop tld 

    return split

def tld(qname: str) -> str: 
    """
    Get the top level domain of a full domain name
    """
    domains = qname.split('.')

    if len(domains) <= 1: 
        return qname

    if domains[-1]: 
        return domains[-1]
    else: 
        return domains[-2]



def ip_to_wire(ip_addr: str): 
    ip_bytes = socket.inet_pton(socket.AF_INET, ip_addr)
    return struct.unpack("I", ip_bytes)[0]

def domain_to_wire(domain: str) -> bytes: 
    domains = domain.split('.')

    wire_domain = b""

    for d in domains: 
        wire_domain += len(d).to_bytes(1)
        wire_domain += d.encode("utf-8")

    wire_domain += b"\x00"
    return wire_domain




