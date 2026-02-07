from dnseventschema import DNSQueryEvent, DNSQType
from recordreceiver import RecordEvent
import argparse
from dnslib import EDNS0
import math
from collections import Counter

class DNSAnalyzer():
    """
    Abstract Base Class for all types of DNS query analyzers
    """

    def analyze (self, dns_event_query: RecordEvent) -> int:
        """
        Process and analyze one single DNS query
        """
        pass

    def report (self) -> str:
        """
        Print and report actions and statistics based on analysis
        """
        pass

# Current Work
class EntropyDNSAnalyzer(DNSAnalyzer):
    """
    DNSAnalyzer child class that analyzes DNS query qnames for different levels of entropy (randomness)
    """

    def analyze(self, dns_event_query: RecordEvent) -> tuple[float, int]:
        # Entropy Analysis
        qname : str = str(dns_event_query.record.questions[0].qname)

        # DNS tunneling most often puts payload data in the left most label. Hence, we will analyze only the left most label. 
        left_label = self._get_leftmost_label(qname)
        label_length = len(left_label)

        # Use Shannon entropy analysis to measure the randomness of the symbol distribution.
        entropy = self._shannon_entropy(left_label)
        # print(f"Qname: {qname} | Entropy: {entropy} | Label Length: {label_length}")

        return (entropy, label_length)
    
    def _get_leftmost_label (self, qname: str) -> str:
        return qname.split(".")[0].lower()
    
    def _shannon_entropy(self, left_label : str) -> float:
        if not left_label:
            return 0.0
        
        counts = Counter(left_label)
        length = len (left_label)

        entropy_val = 0.0
        for count in counts.values():
            p = count / length
            entropy_val -= p * math.log2(p)

        return round(entropy_val, 2)

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


ANALYZER_REGISTRY = {
    'entropy': EntropyDNSAnalyzer,
    'traffic': TrafficDNSAnalyzer
}

def parse_args():
    parser = argparse.ArgumentParser(description="DNS Analysis Options")

    parser.add_argument(
        "--analyzer",
        required=True,
        choices=ANALYZER_REGISTRY.keys(),
        help="Type of DNS analysis to use"
    )

    parser.add_argument(
        "--input",
        required=True,
        help="Path to csv file containing sample DNS queries"
    )
    return parser.parse_args()