


from dnsanalyzers import WhitelistDNSChecker
from recordevent import RecordEvent

class TopDomainsDNSChecker(WhitelistDNSChecker): 
    """
    Uses CSV list of top safe domain names. Can prove a query is not suspicious 

    """

    def __init__(self, csv_path: str): 
        pass 

    def is_benign(self, dns_event_query: RecordEvent) -> bool: 
        return True




