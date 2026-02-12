

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



