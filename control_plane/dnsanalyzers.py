from dnseventschema import DNSQueryEvent
import argparse

class DNSAnalyzer():
    """
    Abstract Base Class for all types of DNS query analyzers
    """

    def process_event (self, dns_event_query: DNSQueryEvent) -> None:
        """
        Process and analyze one single DNS query
        """
        pass

    def report (self) -> None:
        """
        Print and report actions and statistics based on analysis
        """
        pass


class EntropyDNSAnalyzer(DNSAnalyzer):
    """
    DNSAnalyzer child class that analyzes DNS query qnames for different levels of entropy (randomness)
    """
    
    def __init__(self) -> None:
        # TODO
        print("Entropy DNS Analyzer")

    def process_event(self, dns_event_query: DNSQueryEvent) -> None:
        print(dns_event_query)

    def report(self) -> None:
        pass

class TrafficDNSAnalyzer(DNSAnalyzer):
    """
    Placeholder for now
    """

    def __init__(self) -> None:
        # TODO
        print("Traffic DNS Analyzer")

    def process_event(self, dns_event_query: DNSQueryEvent) -> None:
        print(dns_event_query)

    def report(self) -> None:
        pass


