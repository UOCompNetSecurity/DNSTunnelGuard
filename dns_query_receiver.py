
from dataclasses import dataclass 
from enum import Enum
import queue
import threading 
from typing import Callable

class DNSQueryType(Enum): 
    TXT = "TXT"

@dataclass
class DNSQuery: 
    query: str
    ip_address: str
    query_type: DNSQueryType


DEFAULT_MAX_QUEUE_SIZE = 999999


class DNSQueryReceiver: 
    """
    Base class of a DNS query receiver. Where the results are received is up to the derived class implementation. 
    Creates a receiving thread to not block the receiving queue if computation on the query is expensive

    """

    def __init__(self, on_recv: Callable[[DNSQuery], None], max_queue_size=DEFAULT_MAX_QUEUE_SIZE): 
        self.query_queue = queue.Queue(max_queue_size)
        self.recv_thread = threading.Thread(target=self._recv_worker, args=(on_recv,))


    def receive(self): 
        self.recv_thread.start()

        while True: 
            self.query_queue.put(self._receive_query())


    def _recv_worker(self, on_recv): 
        while True: 
            query = self.query_queue.get()
            on_recv(query)


    def _receive_query(self) -> DNSQuery: 
        raise NotImplementedError("_receive_query must be implemented by derived classes of DNSQueryReceiver")



class CSVDNSQueryReceiver(DNSQueryReceiver): 

    def __init__(self, csv_file_path: str, on_recv: Callable[[DNSQuery], None], max_queue_size=DEFAULT_MAX_QUEUE_SIZE): 
        self.csv_file = open(csv_file_path, "r")
        super().__init__(on_recv, max_queue_size)

    def _receive_query(self) -> DNSQuery: 
        line = self.csv_file.readline()
        values = line.split(',')
        query, addr, query_type = values
        return DNSQuery(query=query, ip_address=addr, query_type=DNSQueryType(query_type))


















