
import sys 
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from recordreceiver import CSVRecordReceiver, RecordEvent
from rulewriter import RuleWriter, CSVRuleWriter
from dnseventschema import DNSQueryEvent, DNSQType
from dnsanalyzers import DNSAnalyzer, EntropyDNSAnalyzer, TrafficDNSAnalyzer, ANALYZER_REGISTRY, parse_args
from dnslib import EDNS0


class RecordAnalyzer(): 
    def __init__(self, rule_writer: RuleWriter): 
        self.rule_writer = rule_writer 

    def analyze(self, event: RecordEvent):
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
        # print(dns_query_event)
        
        # TODO Dispatch analysis to the proper analysis class
        args = parse_args()
        analyzer_class = ANALYZER_REGISTRY[args.analyzer]
        dns_analyzer : DNSAnalyzer = analyzer_class()
        dns_analyzer.process_event(dns_query_event)

        """
        qname = event.record.questions[0].qname
        ip = event.src_ip_addr

        with self.rule_writer as r: 
            r.block_domain(qname)
            r.block_ip_address(ip)

        print(f"Blocked domain {qname} and ip address {ip}")
        """

if __name__ == "__main__": 

    """
    if len(sys.argv) < 2: 
        print(f"Usage: python3 {sys.argv[0]} <csv> --analyzer <analysis type>")
        sys.exit(1)
    """

    args = parse_args()

    # ----------------------------
    # Chose derived classes once, write the same code later 
    writer   = CSVRuleWriter("blocked2.csv")

    analyzer = RecordAnalyzer(writer)

    receiver = CSVRecordReceiver(path=args.input, on_recv=analyzer.analyze)
    # ----------------------------

    with receiver: 
        receiver.receive()










