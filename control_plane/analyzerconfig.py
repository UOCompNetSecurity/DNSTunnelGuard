

from configparser import ConfigParser
from dnsanalyzers import DNSAnalyzer 
from trafficanalyzer import TrafficDNSAnalyzer
from entropyanalyzer import EntropyDNSAnalyzer

def parse_analyzer_types(config: ConfigParser) -> list[DNSAnalyzer]: 
    analyzers = []

    if config['analyzer']['entropy'] == 'true': 
        analyzers.append(EntropyDNSAnalyzer())

    if config['analyzer']['traffic'] == 'true': 
        traffic_config = config['trafficanalyzer']
        analyzers.append(TrafficDNSAnalyzer(max_weight=float(traffic_config["max_weight"]), 
                                            ip_minute_distance_threshold= 
                                                float(traffic_config["ip_minute_distance_threshold"]), 
                                            domain_minute_distance_threshold=
                                                float(traffic_config["domain_minute_distance_threshold"]), 
                                            num_queries_for_domain_threshold=
                                                int(traffic_config["num_queries_for_domain_threshold"]), 
                                            num_queries_from_ip_threshold=
                                                int(traffic_config["num_queries_from_ip_threshold"]), 
                                            ip_weight=float(traffic_config["ip_weight"]), 
                                            domain_weight=float(traffic_config["domain_weight"])
                                            ))

    return analyzers


