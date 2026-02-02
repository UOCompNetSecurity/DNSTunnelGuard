
from rulewriter import BPFRuleWriter

def main(): 
    ingress_rule_writer = BPFRuleWriter(
        so_file="./libguard.so", 
        ip_map="blkd_ip_map",
        domain_map="blkd_domain_map"
    )

    with ingress_rule_writer as r: 
        r.unblock_domain("attacker.com")


if __name__ == "__main__": 
    main()



