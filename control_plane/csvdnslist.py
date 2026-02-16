


from dnslist import DNSList

class CSVDomainList(DNSList): 
    """
    Uses CSV list of top safe domain names. Can prove a query is not suspicious 

    """

    def __init__(self, csv_path: str): 
        self.domain_set = set()

        with open(csv_path, "r") as f: 
            for line in f: 
                domain = line.split(",")[1].strip()
                self.domain_set.add(domain)

    def has_domain(self, domain: str) -> bool: 
        if domain.endswith('.'): 
            domain = domain[:-1]

        return domain in self.domain_set 







