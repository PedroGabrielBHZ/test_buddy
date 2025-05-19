import logging
import os

# Set up logging to a file
logfile = os.path.join(os.path.dirname(__file__), "access.log")
logging.basicConfig(
    filename=logfile,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)


def log_ip(ip: str):
    logging.info(f"Request from IP: {ip}")
