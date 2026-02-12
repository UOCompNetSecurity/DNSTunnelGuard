
from trafficanalyzer import TrafficDNSAnalyzer
from recordevent import RecordEvent
from dnslib import DNSRecord, DNSQuestion
import pytest
from datetime import datetime

@pytest.fixture
def event() -> RecordEvent: 
    return RecordEvent(src_ip_addr="192.168.55.1", 
                       timestamp=datetime.now(), 
                       record=DNSRecord(q=DNSQuestion(qname="attacker.com")))

def get_default_traffic_analyzer(ip_weight: float, domain_weight: float): 
    return TrafficDNSAnalyzer(weight_percentage=1, 
                              ip_minute_difference_threshold=5,
                              domain_minute_difference_threshold=5, 
                              num_queries_for_domain_threshold=2, 
                              num_queries_from_ip_threshold=2, 
                              ip_weight=ip_weight, 
                              domain_weight=domain_weight)


def test_ip_analyzer_full_suspicious(event: RecordEvent): 
    """
    Test full suspicion percentage on an analyzer that only cares about repeated IP addresses 
    """
    ip_analyzer = get_default_traffic_analyzer(1, 0)
    sus_level = 0
    for _ in range(2): 
        sus_level = ip_analyzer.analyze(event)
    assert sus_level == 1.0


def test_ip_analyzer_half_suspicious(event: RecordEvent): 
    """
    Test half suspicion percentage on an analyzer that only cares about repeated IP addresses 
    """
    ip_analyzer = get_default_traffic_analyzer(1, 0)
    sus_level = ip_analyzer.analyze(event)
    assert sus_level == 0.5

def test_domain_analyzer_full_suspicious(event: RecordEvent): 
    """
    Test full suspicion percentage on an analyzer that only cares about repeated domain names 
    """

    domain_analyzer = get_default_traffic_analyzer(0, 1)
    sus_level = 0
    for _ in range(2): 
        sus_level = domain_analyzer.analyze(event)
    assert sus_level == 1.0


def test_domain_analyzer_half_suspicious(event: RecordEvent): 
    """
    Test half suspicion percentage on an analyzer that only cares about repeated domain names 
    """
    domain_analyzer = get_default_traffic_analyzer(0, 1)
    sus_level = domain_analyzer.analyze(event)
    assert sus_level == 0.5


def test_even_split_analyer_full_suspicious(event: RecordEvent): 
    even_split_analyzer = get_default_traffic_analyzer(0.5, 0.5)
    sus_level = 0
    for _ in range(2): 
        sus_level = even_split_analyzer.analyze(event)
    assert sus_level == 1.0


def test_even_split_analyer_half_suspicious(event: RecordEvent): 
    even_split_analyzer = get_default_traffic_analyzer(0.5, 0.5)
    sus_level = even_split_analyzer.analyze(event)
    assert sus_level == 0.5

def test_even_split_over_suspicious(event: RecordEvent): 
    even_split_analyzer = get_default_traffic_analyzer(0.5, 0.5)
    sus_level = 0
    for i in range(3): 
        sus_level = even_split_analyzer.analyze(event)
    assert sus_level == 1.0






























