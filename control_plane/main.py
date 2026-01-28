
from rulewriter import BPFRuleWriter
import ctypes

def main(): 
    ingress_rule_writer = BPFRuleWriter(
        so_file="./libguard.so", 
        src_ip_map="egress_src_ip", 
        dst_ip_map="egress_dst_ip"
    )

    with ingress_rule_writer as r: 
        r.block_src_ip_address(10)


if __name__ == "__main__": 
    main()



