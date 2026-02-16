

import parseutils

def test_split_labels(): 

    domain = "evil.attacker.com"

    split = parseutils.split_labels(domain)

    assert split == ["evil.attacker.com", "attacker.com", "com"]


def test_split_labels_only_tld(): 
    domain = ".com"
    split = parseutils.split_labels(domain)

    assert split == ['com']

def test_split_labels_empty(): 
    split = parseutils.split_labels("")
    assert not split

def test_extra_dot(): 
    domain = "evil.attacker.com."
    split = parseutils.split_labels(domain)
    assert split == ["evil.attacker.com", "attacker.com", "com"]

def test_tld(): 

    tld = parseutils.tld("attacker.com")
    assert tld == "com"

def test_tld_with_end_dot(): 
    tld = parseutils.tld("attacker.com.")
    assert tld == "com"

def test_tld_only_tld(): 
    tld = parseutils.tld(".com")
    assert tld == "com"

def test_tld_empty(): 
    tld = parseutils.tld("")
    assert not tld



