
import queue
import threading 
import time
from typing import Callable
from dnslib import DNSRecord, DNSQuestion
import csv 
import datetime
from dataclasses import dataclass 

DEFAULT_MAX_QUEUE_SIZE = 100_000


@dataclass 
class RecordEvent: 
    """
    Event for either query or response receival 
    """
    record: DNSRecord 
    timestamp: datetime.datetime
    src_ip_addr: str

class RecordReceiver: 
    """
    Base class of a DNS record receiver. Where the results are received is up to the derived class implementation. 
    Creates a receiving thread to not block the receiving queue if computation on the query is expensive

    """

    def __init__(self, on_recv: Callable[[RecordEvent], None], max_queue_size=DEFAULT_MAX_QUEUE_SIZE): 
        self._query_queue = queue.Queue(max_queue_size)
        self._recv_thread = threading.Thread(target=self._on_recv_worker, args=(on_recv,))

    def __enter__(self): 
        self._recv_thread.start()
        return self 

    def __exit__(self, exc_type, exc_value, traceback): 
        self._recv_thread.join()
        return False

    def receive(self): 
        """
        Begin the receive loop to receive records from source 
        """
        while True: 
            record = self._receive_record()
            if record is None: 
                break 
            self._query_queue.put(record)
        self._query_queue.put(None) # terminate recv thread 


    # ---------------- 
    # No need to use these if using "with" context
    def start_on_recv_thread(self): 
        self._recv_thread.start()

    def join_on_recv_thread(self): 
        self._recv_thread.join()
    # --------------- 

    def _on_recv_worker(self, on_recv): 
        """
        Runs in a seperate thread, executing the users recv function from records pushed to the query queue 

        """
        while True: 
            query = self._query_queue.get()
            if query is None: 
                break 
            on_recv(query)

    def _receive_record(self) -> RecordEvent | None: 
        """
        Implemented by derived class, return parsed RecordEvent or None if receiving is complete 

        """
        raise NotImplementedError("_receive_record must be implemented by derived classes of DNSQueryReceiver")



class CSVRecordReceiver(RecordReceiver): 

    def __init__(self, path: str, on_recv: Callable[[RecordEvent], None], max_queue_size=DEFAULT_MAX_QUEUE_SIZE, sleep_time: float | None=None): 
        self.sleep_time = sleep_time
        self.csv_file = open(path, "r")
        self.csv_reader = csv.reader(self.csv_file)
        next(self.csv_reader) # skip the first line 
        super().__init__(on_recv, max_queue_size)

    def __exit__(self, exc_type, exc_value, traceback): 
        self.csv_file.close()
        super().__exit__(exc_type, exc_value, traceback)
        return False

    def close(self): 
        self.csv_file.close()

    def _receive_record(self) -> RecordEvent | None: 
        if self.sleep_time is not None: 
            time.sleep(self.sleep_time)

        try: 
            row = next(self.csv_reader) 
        except StopIteration: 
            return None

        qname, ip_addr = row

        record = DNSRecord(q=DNSQuestion(qname=qname))

        return RecordEvent(record=record, timestamp=datetime.datetime.now(), src_ip_addr=ip_addr)



















