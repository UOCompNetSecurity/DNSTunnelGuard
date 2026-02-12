

from matchgram import MatchGram, gram_string
import pytest


@pytest.fixture
def matchgram() -> MatchGram: 
    return MatchGram(gram_num=2)

def test_gram_string(): 
    split = gram_string("attacker.com", 2)
    assert split == ["at", "tt", "ta", "ac", "ck", "ke", "er", "r.", ".c", "co", "om"]

def test_insert_match(matchgram: MatchGram): 
    domain = "attacker.com"
    matchgram.insert(domain)
    assert domain in matchgram
    assert "random.com" not in matchgram


def test_empty(matchgram: MatchGram): 
    matchgram.insert("")
    assert "" not in matchgram


def test_similar_domains(matchgram: MatchGram): 
    domain = "attacker.com"
    domain2 = "attaccer.com"
    matchgram.insert(domain)
    matchgram.insert(domain2)

    assert domain in matchgram
    assert domain2 in matchgram



