

import parseutils

def test_parse_qname_no_tld(): 

    domain = "evil.attacker.com"

    split = parseutils.parse_qname_no_tld(domain)

    assert split == ["evil.attacker.com", "attacker.com"]


def test_parse_qname_no_tld_only_tld(): 
    domain = ".com"
    split = parseutils.parse_qname_no_tld(domain)

    assert not split

def test_parse_qname_no_tld_only_tld_with_end_dot(): 
    split = parseutils.parse_qname_no_tld(".com.")

    assert not split

def test_parse_qname_no_tld_empty(): 
    split = parseutils.parse_qname_no_tld("")

    assert not split

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
