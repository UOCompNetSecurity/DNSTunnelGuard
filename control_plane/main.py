
from rulewriter import BPFRuleWriter
import ctypes

def main(): 
    ingress_rule_writer = BPFRuleWriter(
        so_file="./libguard.so", 
        ip_map="ip_map", 
    )

    with ingress_rule_writer as r: 
        r.block_ip_address("192.168.55.1")


if __name__ == "__main__": 
    main()



