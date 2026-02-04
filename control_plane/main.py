
from argparse import ArgumentParser
from configparser import ConfigParser
from guardconfig import parse_guard_types
from analyzerconfig import parse_analyzer_types
from guardcontroller import GuardController
import sys


def main(): 
    parser = ArgumentParser(description="DNS Tunnel Guard Options")

    parser.add_argument(
        '--config_path', 
        required=False, 
        help='Path to config file'
    )

    parser.add_argument(
        '--csv_firewall_path',
        required=False,
        help='Path to emulated CSV file of blocked IP addresses and domain names'
    )

    parser.add_argument(
        '--csv_records_path', 
        required=False, 
        help='Path to emulated CSV file of DNS records'
    )

    args = parser.parse_args()

    config_path = "config.ini" if args.config_path is None else args.config_path

    config = ConfigParser()
    config.read(config_path)

    try: 
        record_receiver, firewall = parse_guard_types(args, config)
        analyzers = parse_analyzer_types(config)

    except Exception as e: 
        print(f"Invalid configuration: {str(e)}")
        sys.exit(1)

    guard_controller = GuardController(analyzers, firewall, sus_threshold=1, print_reports=True)

    record_receiver.set_on_recv(guard_controller.process_record)

    with record_receiver: 
        record_receiver.receive()


if __name__ == "__main__": 
    main()



