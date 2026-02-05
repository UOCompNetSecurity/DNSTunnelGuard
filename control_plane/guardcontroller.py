
from dnsanalyzers import DNSAnalyzer 
from recordevent import RecordEvent
from firewall import Firewall

import logging
logger = logging.getLogger(__name__)

class GuardController: 
    """
    Manages analyzers and firewall to dispatch the different analyizers and block the IP and domain 
    if these analyzers find the queriy suspicious

    """

    def __init__(self, analyzers: list[DNSAnalyzer], firewall: Firewall, sus_threshold: int): 
        self.analyzers = analyzers
        self.firewall = firewall
        self.sus_threshold = sus_threshold

    def process_record(self, event: RecordEvent): 
        """
        Callback to be used on every record event 
        """
        logging.debug(f"Processing Query {event}")

        sus_weight = 0 

        for analyzer in self.analyzers: 
            sus_weight += analyzer.analyze(event)
            logging.info("Analyzer Report: " + analyzer.report())

        if sus_weight > self.sus_threshold: 

            self.firewall.block_ip_address(event.src_ip_addr)
            for q in event.record.questions: 
                logging.warning(f"Suspicious query detected, blocking domain: {str(q.qname)} from IP address: {event.src_ip_addr}")

                sub_domains = self._parse_qname(str(q.qname))

                for sub_domain in sub_domains: 
                    self.firewall.block_domain(sub_domain)



    def _parse_qname(self, qname: str) -> list[str]: 
        domain = qname.split('.')

        if not domain[-1]: 
            domain.pop()

        domain.pop()

        return domain 



        

