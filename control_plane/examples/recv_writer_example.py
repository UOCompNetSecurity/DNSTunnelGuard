
import sys 
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from recordreceiver import CSVRecordReceiver, RecordEvent
from rulewriter import RuleWriter, CSVRuleWriter


class RecordAnalyzer(): 
    def __init__(self, rule_writer: RuleWriter): 
        self.rule_writer = rule_writer 

    def analyze(self, event: RecordEvent): 
        qname = event.record.questions[0].qname
        ip = event.src_ip_addr
        self.rule_writer.block_domain(qname)
        self.rule_writer.block_ip_address(ip)
        print(f"Blocked domain {qname} and ip address {ip}")

if __name__ == "__main__": 

    if len(sys.argv) < 2: 
        print(f"Usage: python3 {sys.argv[0]} <csv>")
        sys.exit(1)

    # ----------------------------
    # Chose derived classes once, write the same code later 
    writer   = CSVRuleWriter("blocked.csv")

    analyzer = RecordAnalyzer(writer)

    receiver = CSVRecordReceiver(path=sys.argv[1], on_recv=analyzer.analyze)
    # ----------------------------

    with receiver: 
        receiver.receive()










