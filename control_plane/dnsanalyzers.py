from dnseventschema import DNSQueryEvent

class DNSAnalyzer():
    """
    Abstract Base Class for all types of DNS query analyzers
    """

    def process_event(self, dns_event_query: DNSQueryEvent) -> int:
        """
        Process and analyze one single DNS query
        Returns weight of suspicion of being tunneling 
        """
        raise NotImplementedError("process event method not implemented")

    def report(self) -> None:
        """
        Print and report actions and statistics based on analysis
        """
        raise NotImplementedError("report method implemented")


class EntropyDNSAnalyzer(DNSAnalyzer):
    """
    DNSAnalyzer child class that analyzes DNS query qnames for different levels of entropy (randomness)
    """
    
    def __init__(self) -> None:
        # TODO
        print("Entropy DNS Analyzer")

    def process_event(self, dns_event_query: DNSQueryEvent) -> int:
        print(dns_event_query)
        return 0 

    def report(self) -> None:
        return 

class TrafficDNSAnalyzer(DNSAnalyzer):
    """
    Placeholder for now
    """

    def __init__(self) -> None:
        # TODO
        print("Traffic DNS Analyzer")

    def process_event(self, dns_event_query: DNSQueryEvent) -> int:
        print(dns_event_query)
        return 0 

    def report(self) -> None:
        return 

