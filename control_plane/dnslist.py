
class DNSList: 
    """
    DNS checkers have the power to rule a domain 100% unsuspicious 
    and pass through without further inspection 

    """


    def has_ip_address(self, ip: str): 
        raise NotImplementedError("has_ip_address method not implemented")

    def has_domain(self, domain: str): 
        raise NotImplementedError("has_domain method not implemented")

