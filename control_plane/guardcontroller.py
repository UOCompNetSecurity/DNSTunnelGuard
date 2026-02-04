
from dnsanalyzers import DNSAnalyzer 
from recordreceiver import RecordEvent
from dnseventschema import DNSQueryEvent, DNSQType
from firewall import Firewall
from dnslib import EDNS0

class GuardController: 
    """
    Manages analyzers and firewall to dispatch the different analyizers and block the IP and domain 
    if these analyzers find the queriy suspicious

    """

    def __init__(self, analyzers: list[DNSAnalyzer], firewall: Firewall, sus_threshold: int, print_reports=False): 
        self.analyzers = analyzers
        self.firewall = firewall
        self.sus_threshold = sus_threshold
        self.print_reports = print_reports

    def process_record(self, event: RecordEvent): 
        """
        Callback to be used on every record event 
        """
        # Grab the data to analyze from the record event
        timestamp = event.timestamp
        src_ip_addr = event.src_ip_addr
        qname = event.record.questions[0].qname
        qtype = event.record.questions[0].qtype

        raw = event.record.pack()
        query_size = len(raw)

        edns_size = None
        # for rr in event.record.ar:
        #     if isinstance(rr.rdata, EDNS0):
        #         edns_size = rr.rdata.udp_len
        #         break

        # Build the query event object to pass along to analysis class method
        dns_query_event = DNSQueryEvent(timestamp, src_ip_addr, str(qname), DNSQType(qtype), query_size, edns_size)

        sus_weight = 0 

        for analyzer in self.analyzers: 
            sus_weight += analyzer.process_event(dns_query_event)
            if self.print_reports: 
                analyzer.report()

        if sus_weight > self.sus_threshold: 
            self.firewall.block_ip_address(src_ip_addr)
            split_qname = qname.split('.')
            split_qname.pop()
            mal_domain = split_qname.join()
            self.firewall.block_domain(mal_domain)
        

