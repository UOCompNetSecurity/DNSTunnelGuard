
from rulewriter import BPFRuleWriter

def main(): 
    ingress_rule_writer = BPFRuleWriter(
        so_file="./libguard.so", 
        dst_ip_map="dst_ip_map",
        domain_map="domain_map"
    )

    with ingress_rule_writer as r: 
        r.block_domain("attacker.com")


if __name__ == "__main__": 
    main()



