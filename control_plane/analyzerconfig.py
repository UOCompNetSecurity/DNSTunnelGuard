

from configparser import ConfigParser
from dnsanalyzers import DNSAnalyzer 
from trafficanalyzer import TrafficDNSAnalyzer
from entropyanalyzer import EntropyDNSAnalyzer

def parse_analyzer_types(config: ConfigParser) -> list[DNSAnalyzer]: 
    analyzers = []

    if config['analyzer']['entropy'] == 'true': 
        entropy_config = config['entropyanalyzer']
        analyzers.append(EntropyDNSAnalyzer(weight_percentage=float(entropy_config["weight_percentage"])))

    if config['analyzer']['traffic'] == 'true': 
        traffic_config = config['trafficanalyzer']
        analyzers.append(TrafficDNSAnalyzer(weight_percentage=float(traffic_config["weight_percentage"]), 
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


