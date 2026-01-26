
from rulewriter import BPFRuleWriter

def main(): 
    rule_writer = BPFRuleWriter("./libguard.so", "ip_block_map")
    rule_writer.block_ip_address("10.0.2.50")

if __name__ == "__main__": 
    main()



