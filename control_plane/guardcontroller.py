
from dnsanalyzers import DNSAnalyzer 
from recordevent import RecordEvent
from firewall import Firewall
import parseutils

import logging
logger = logging.getLogger(__name__)

class GuardController: 
    """
    Manages analyzers and firewall to dispatch the different analyizers and block the IP and domain 
    if these analyzers find the queriy suspicious

    """

    def __init__(self, analyzers: list[DNSAnalyzer], firewall: Firewall, sus_percentage_threshold: float): 
        self.analyzers = analyzers
        self.firewall = firewall
        self.sus_percentage_threshold = sus_percentage_threshold

    def process_record(self, event: RecordEvent): 
        """
        Callback to be used on every record event 
        """
        logging.debug(f"Processing Query {event}")

        sus_percentage = 0.0 

        for analyzer in self.analyzers: 
            sus_percentage += analyzer.analyze(event) * analyzer.weight_percentage
            logging.info("Analyzer Report: " + analyzer.report())

        if sus_percentage >= self.sus_percentage_threshold: 

            self.firewall.block_ip_address(event.src_ip_addr)
            for q in event.record.questions: 
                logging.warning(f"Suspicious query detected, blocking domain: {str(q.qname)} from IP address: {event.src_ip_addr}")

                sub_domains = parseutils.parse_qname_no_tld(str(q.qname))
                tld = parseutils.tld(str(q.qname))

                for sub_domain in sub_domains: 
                    self.firewall.block_domain(f"{sub_domain}.{tld}")






        

