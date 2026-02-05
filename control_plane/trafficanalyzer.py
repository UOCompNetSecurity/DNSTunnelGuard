

from dnsanalyzers import DNSAnalyzer
from recordevent import RecordEvent
from collections import defaultdict
from datetime import datetime

class TrafficDNSAnalyzer(DNSAnalyzer):
    """
    Analyze a query based on traffic 
    """

    def __init__(self): 

        self.num_queries_from_ip = defaultdict(int)
        self.num_queries_for_domain = defaultdict(int)


    def analyze(self, dns_event_query: RecordEvent) -> int:
        return 2 

    def report(self) -> str:
        return ""

