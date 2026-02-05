

from configparser import ConfigParser
import logging 

def setup_logging(config: ConfigParser): 

    level_str = config["logging"]["level"]
    level = logging.DEBUG

    match level_str: 
        case "DEBUG": 
            level = logging.DEBUG
        case "INFO": 
            level = logging.INFO
        case "WARNING": 
            level = logging.WARNING
        case "ERROR": 
            level = logging.ERROR
        case "CRITICAL": 
            level = logging.CRITICAL
        case _: 
            raise Exception("Invalid logging level")

    output = config["logging"]["output"]

    if output != "stdout": 
        logging.basicConfig(filename=output, level=level)
    else: 
        logging.basicConfig(level=level)



