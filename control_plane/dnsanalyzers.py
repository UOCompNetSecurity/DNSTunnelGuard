
from recordevent import RecordEvent

class DNSAnalyzer:
    """
    Abstract Base Class for all types of DNS query analyzers
    """

    def __init__(self, weight_percentage: float, can_whitelist=False): 
        self.weight_percentage = weight_percentage
        self.can_whitelist = can_whitelist

    def analyze(self, dns_event_query: RecordEvent) -> float:
        """
        Process and analyze one single DNS query
        Returns weight of suspicion of being tunneling 
        """
        raise NotImplementedError("process event method not implemented")

    def report(self) -> str:
        """
        Return reported actions and statistics based on analysis
        """
        raise NotImplementedError("report method not implemented")



class WhitelistDNSChecker: 
    """
    DNS analyzers that have the power to rule a domain 100% unsuspicious 
    and pass through without further inspection 

    """

    def is_benign(self, dns_event_query: RecordEvent) -> bool: 
        raise NotImplementedError("check method not implemented")

