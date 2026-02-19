import parseutils


def test_split_subdomains():

    domain = "evil.attacker.com"

    split = parseutils.split_subdomains(domain)

    assert split == ["evil.attacker.com", "attacker.com", "com"]


def test_split_subdomains_only_tld():
    domain = ".com"
    split = parseutils.split_subdomains(domain)

    assert split == ["com"]


def test_split_subdomains_empty():
    split = parseutils.split_subdomains("")
    assert not split


def test_extra_dot():
    domain = "evil.attacker.com."
    split = parseutils.split_subdomains(domain)
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
