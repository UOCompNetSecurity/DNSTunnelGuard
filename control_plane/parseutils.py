

def parse_qname_no_tld(qname: str) -> list[str]: 
    """
    Splits a qname into parts, excludes the top level domain 
    """
    domains = qname.split('.')

    if not domains[-1]: 
        domains.pop()

    domains.pop()

    return [".".join(domains[i:]) for i in range(len(domains))]

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



