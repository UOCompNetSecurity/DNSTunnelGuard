
from recordevent import RecordEvent

class DNSAnalyzer():
    """
    Abstract Base Class for all types of DNS query analyzers
    """

    def analyze(self, dns_event_query: RecordEvent) -> int:
        """
        Process and analyze one single DNS query
        Returns weight of suspicion of being tunneling 
        """
        raise NotImplementedError("process event method not implemented")

    def report(self) -> str:
        """
        Return reported actions and statistics based on analysis
        """
        raise NotImplementedError("report method implemented")


class EntropyDNSAnalyzer(DNSAnalyzer):
    """
    DNSAnalyzer child class that analyzes DNS query qnames for different levels of entropy (randomness)
    """

    def analyze(self, dns_event_query: RecordEvent) -> int:
        return 2 

    def report(self) -> str:
        return ""

class TrafficDNSAnalyzer(DNSAnalyzer):
    """
    Placeholder for now
    """


    def analyze(self, dns_event_query: RecordEvent) -> int:
        return 2 

    def report(self) -> str:
        return ""

