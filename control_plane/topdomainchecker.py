


from dnsanalyzers import DNSChecker
from recordevent import RecordEvent

class TopDomainsDNSChecker(DNSChecker): 
    """
    Uses CSV list of top safe domain names. Can prove a query is not suspicious 

    """

    def __init__(self, csv_path: str): 
        self.domain_set = set()

        with open(csv_path, "r") as f: 
            for line in f: 
                domain = line.split(",")[1].strip()
                self.domain_set.add(domain)

    def is_benign(self, dns_event_query: RecordEvent) -> bool: 
        for question in dns_event_query.record.questions: 

            domain = str(question.qname)
            if domain.endswith('.'): 
                domain = domain[:-1]

            if domain not in self.domain_set: 
                return False
        return True





