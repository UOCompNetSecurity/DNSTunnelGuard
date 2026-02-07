
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

    def analyze(self, event: RecordEvent, dns_analyzer: DNSAnalyzer):
        dns_analyzer.analyze(event)

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

    analyzer_class = ANALYZER_REGISTRY[args.analyzer]
    dns_analyzer : DNSAnalyzer = analyzer_class()

    # ----------------------------
    # Chose derived classes once, write the same code later 
    writer   = CSVRuleWriter("blocked2.csv")

    analyzer = RecordAnalyzer(writer)

    receiver = CSVRecordReceiver(path=args.input, on_recv=analyzer.analyze, dns_analyzer=dns_analyzer)
    # ----------------------------

    with receiver: 
        receiver.receive()

    dns_analyzer.report()