

from topdomainchecker import TopDomainsDNSChecker
from recordevent import RecordEvent
from dnslib import DNSRecord, DNSQuestion
import pytest
from datetime import datetime



@pytest.fixture
def checker(): 
    return TopDomainsDNSChecker("./data/top-1m.csv")


def create_event(qname: str) -> RecordEvent: 
    event = RecordEvent(src_ip_addr="192.168.55.1", 
                        record=DNSRecord(q=DNSQuestion(qname=qname)),
                        timestamp=datetime.now())
    return event  

def test_topdomains(checker: TopDomainsDNSChecker): 
    assert checker.is_benign(create_event("google.com"))
    assert checker.is_benign(create_event("edge.microsoft.com"))
    assert not checker.is_benign(create_event("fjdklajfkdlsafalen"))


