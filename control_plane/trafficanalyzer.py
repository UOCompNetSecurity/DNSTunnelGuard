

from dnsanalyzers import DNSAnalyzer
from recordevent import RecordEvent
from datetime import datetime
from collections import defaultdict, deque
import parseutils



class TrafficDNSAnalyzer(DNSAnalyzer):
    """
    Analyze a DNS query based on traffic history

    """

    def __init__(self, weight_percentage: float, 
                 ip_minute_difference_threshold: float, 
                 domain_minute_difference_threshold: float,
                 num_queries_for_domain_threshold: int, 
                 num_queries_from_ip_threshold: int, 
                 ip_weight: float, 
                 domain_weight: float): 
        """
        weight_percentage: 
            Used to store weight percentage towards analyzer, not used in analyze calculation 
        ip_minute_difference_threshold: 
            The max threshold in minutes IP addresses should be kept in history
        domain_minute_difference_threshold: 
            The max threshold in minutes domains should be kept in history
        num_queries_threshold: 
            Number of queries needed for 100% suspicion for domain name reuse
        num_queries_from_ip_threshold: 
            Number of queries needed for 100% suspicion for queries from the same ip address
        ip_weight: 
            The weight from seeing repeated IP addresses holds in final suspicion value
        domain_weight: 
            The weight from seeing repeated domain names holds in final suspicion value  

        """

        super().__init__(weight_percentage)
        assert num_queries_for_domain_threshold > 0 and num_queries_from_ip_threshold > 0
        self.ip_minute_difference_threshold     = ip_minute_difference_threshold 
        self.domain_minute_difference_threshold = domain_minute_difference_threshold
        self.ip_history     = defaultdict(deque[datetime])
        self.domain_history = defaultdict(deque[datetime])
        self.num_queries_for_domain_threshold = num_queries_for_domain_threshold 
        self.num_queries_from_ip_threshold = num_queries_from_ip_threshold
        self.ip_sus_weight = ip_weight 
        self.domain_sus_weight = domain_weight 


    def analyze(self, dns_event_query: RecordEvent) -> float:
        """
        Analyze a query based on traffic history for the domains and source IP address

        Returns an unweighted suspicion percentage
        
        """

        ip_address = dns_event_query.src_ip_addr
        sub_domains = []
        for question in dns_event_query.record.questions: 
            qname = str(question.qname)

            domains = parseutils.parse_qname_no_tld(qname)

            for domain in domains: 
                self.domain_history[domain].append(dns_event_query.timestamp)
                self.ip_history[ip_address].append(dns_event_query.timestamp)

            sub_domains.extend(domains)

        self._reap_old_queries(sub_domains, ip_address)


        # For each sub domain, find the domain that is most suspicious 
        max_domain_sus_percentage = 0.0
        for domain in sub_domains: 
            num_queries = len(self.domain_history[domain])
            domain_sus_percentage = num_queries / self.num_queries_for_domain_threshold
            max_domain_sus_percentage = max(domain_sus_percentage, max_domain_sus_percentage)

        num_queries_from_ip = len(self.ip_history[ip_address])
        ip_sus_percentage = num_queries_from_ip / self.num_queries_from_ip_threshold

        sus_percentage = (ip_sus_percentage * self.ip_sus_weight) + \
                         (max_domain_sus_percentage * self.domain_sus_weight)

        return min(1.0, sus_percentage)


    def _reap_old_queries(self, sub_domains: list[str], ip_address: str): 
        """
        Remove queries greater than the max time difference threshold set in constructor

        """

        now = datetime.now()

        get_next_timestamp = lambda history, key: history[key][0] if history[key] else None
        is_old = lambda now, timestamp, threshold: (now - timestamp).total_seconds() / 60 > threshold

        for domain in sub_domains: 
            domain_timestamp = get_next_timestamp(self.domain_history, domain)
            while domain_timestamp and is_old(now, domain_timestamp, self.domain_minute_difference_threshold): 
                self.domain_history[domain].popleft()
                domain_timestamp = get_next_timestamp(self.domain_history, domain)

        ip_timestamp = get_next_timestamp(self.ip_history, ip_address)
        while ip_timestamp and is_old(now, ip_timestamp, self.ip_minute_difference_threshold): 
            self.ip_history[ip_address].popleft()
            ip_timestamp = get_next_timestamp(self.ip_history, ip_address)


    def report(self) -> str:
        report_str = f"Traffic Analyzer Report: \n \
                       IP address history: {self.ip_history}\n \
                       Domain history: {self.domain_history}"  

        return report_str


