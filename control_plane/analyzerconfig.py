

from configparser import ConfigParser
from dnsanalyzers import DNSAnalyzer, EntropyDNSAnalyzer,TrafficDNSAnalyzer 

def parse_analyzer_types(config: ConfigParser) -> list[DNSAnalyzer]: 
    analyzers = []

    if config['analyzer']['entropy'] == 'true': 
        analyzers.append(EntropyDNSAnalyzer())

    if config['analyzer']['traffic'] == 'true': 
        analyzers.append(TrafficDNSAnalyzer())

    return analyzers


