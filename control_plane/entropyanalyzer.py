

from dnsanalyzers import DNSAnalyzer
from recordevent import RecordEvent

class EntropyDNSAnalyzer(DNSAnalyzer):
    """
    DNSAnalyzer child class that analyzes DNS query qnames for different levels of entropy (randomness)
    """

    def analyze(self, dns_event_query: RecordEvent) -> int:
        return 2 

    def report(self) -> str:
        return ""


