

from csvdnslist import CSVDomainList
import pytest


@pytest.fixture
def checker(): 
    return CSVDomainList("./data/top-1m.csv")


def test_topdomains(checker: CSVDomainList): 
    assert checker.has_domain("google.com")
    assert checker.has_domain("edge.microsoft.com")
    assert not checker.has_domain("fjdklajfkdlsafalen")


