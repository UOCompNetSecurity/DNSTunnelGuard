

from dnsanalyzers import DNSAnalyzer 
from recordreceiver import RecordEvent
from dnseventschema import DNSQueryEvent, DNSQType
from firewall import Firewall
from dnslib import EDNS0

class GuardController: 

    def __init__(self, analyzers: list[DNSAnalyzer], firewall: Firewall): 
        self.analyzers = analyzers
        self.firewall = firewall

    def process_record(self, event: RecordEvent): 
        # Grab the data to analyze from the record event
        timestamp = event.timestamp
        src_ip_addr = event.src_ip_addr
        qname = event.record.questions[0].qname
        qtype = event.record.questions[0].qtype

        raw = event.record.pack()
        query_size = len(raw)

        edns_size = None
        for rr in event.record.ar:
            if isinstance(rr.data, EDNS0):
                edns_size = rr.rdata.udp_len
                break

        # Build the query event object to pass along to analysis class method
        dns_query_event = DNSQueryEvent(timestamp, src_ip_addr, str(qname), DNSQType(qtype), query_size, edns_size)

        for analyzer in self.analyzers: 
            # For each analyzer, check if the dns query is sus. if so, block the source ip address and domain
            # Also, make sure to block not only the whole domain but the sub domains of interest to, i.e.
            # if its jfkdl.attacker.com, block  jfkdl.attacker.com and attacker.com, but not .com
            pass 























