

from domainlist import DomainList
import pytest


@pytest.fixture
def checker(): 
    return DomainList("./data/whitelist.txt")


def test_topdomains(checker: DomainList): 
    assert checker.has_domain("google.com")
    assert checker.has_domain("edge.microsoft.com")
    assert not checker.has_domain("fjdklajfkdlsafalen")


