
import csv 


class RuleWriter: 
    """
    Abstract class for writing 

    """

    def block_domain(self, domain: str): 
        raise NotImplementedError("block_domain not implemented")

    def block_ip_address(self, ip_address: str): 
        raise NotImplementedError("block_ip_address not implemented")


class CSVRuleWriter(RuleWriter): 

    def __init__(self, path: str): 
        self._csv_file = open(path, "w")
        self._csv_writer = csv.writer(self._csv_file)
        self._csv_writer.writerow(["domain", "ip address"])

    def __del__(self):
        if hasattr(self, "_csv_file") and not self._csv_file.closed:
            self._csv_file.close()

    def block_domain(self, domain: str): 
        self._csv_writer.writerow([domain, ""])

    def block_ip_address(self, ip_address: str): 
        self._csv_writer.writerow(["", ip_address])








