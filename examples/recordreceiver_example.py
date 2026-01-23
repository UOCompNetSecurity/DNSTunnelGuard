
import sys 
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from recordreceiver import CSVRecordReceiver, RecordEvent

def on_recv(event: RecordEvent): 
    print(event)



if __name__ == "__main__": 

    if len(sys.argv) < 2: 
        print(f"Usage: python3 {sys.argv[0]} <csv>")
        sys.exit(1)

    with CSVRecordReceiver(path=sys.argv[1], on_recv=on_recv) as r: 
        r.receive()




