
from dnsanalyzers import DNSAnalyzer 
from dnslist import DNSList
from recordevent import RecordEvent
from firewall import Firewall
import parseutils

import logging
logger = logging.getLogger(__name__)

class GuardController: 
    """
    Manages analyzers and firewall to dispatch the different analyizers and block the IP and domain 
    if these analyzers find the query suspicious

    """

    def __init__(self, 
                 whitelists: list[DNSList], 
                 analyzers: list[DNSAnalyzer], 
                 firewall: Firewall, 
                 sus_percentage_threshold: float, 
                 tld_list: DNSList | None):
        """
        analyzers: 
            List of analyzers to analyze each query 
        firewall:
            firewall used to block IP's and domains 
        sus_percentage_threshold: 
            Percentage that if a query exceeds this sus threshold, the srouce IP address and domain queried 
            for are blocked 
        tld_checker: 
            CSV checker that can tell if a sub domain is a TLD 

        """
        self.whitelists = whitelists
        self.analyzers = analyzers
        self.firewall = firewall
        self.sus_percentage_threshold = sus_percentage_threshold
        self.tld_list = tld_list

    def process_record(self, event: RecordEvent): 
        """
        Callback to be used on every record event 
        """
        logging.debug(f"Processing Query {event}")
        qnames = [str(question.qname) for question in event.record.questions]

        for wl in self.whitelists: 
            for q in qnames: 
                if wl.has_domain(q): 
                    logging.debug("Query found benign")
                    return 

        sus_percentage = 0.0 

        for analyzer in self.analyzers: 
            sus_percentage += analyzer.analyze(event) * analyzer.weight_percentage
            logging.info("Analyzer Report: " + analyzer.report())

        if sus_percentage >= self.sus_percentage_threshold: 

            self.firewall.block_ip_address(event.src_ip_addr)
            for q in qnames: 
                logging.warning(f"Suspicious query detected, blocking domain: {str(q)} from IP address: {event.src_ip_addr}")

                sub_domains = parseutils.split_labels(q)

                for sub_domain in sub_domains: 
                    # do not block listed top level domains 
                    if self.tld_list is None or not self.tld_list.has_domain(sub_domain): 
                        self.firewall.block_domain(sub_domain)






        

