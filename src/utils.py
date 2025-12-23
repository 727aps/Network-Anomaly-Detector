import psutil
import logging
from rich.console import Console

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = Console()

def get_network_interfaces():
    """
    Detects and returns a list of active network interfaces.
    """
    interfaces = []
    for interface, snics in psutil.net_if_addrs().items():
        if any(snic.family == psutil.AF_LINK for snic in snics):
            interfaces.append(interface)
    return interfaces

def setup_logging(log_level='INFO', log_file=None):
    """
    Configures the logging module.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

def log_alert(alert_message, level='ERROR'):
    """
    Logs an alert message with the specified level.
    """
    if level == 'INFO':
        logging.info(f"[ALERT] {alert_message}")
    elif level == 'WARNING':
        logging.warning(f"[ALERT] {alert_message}")
    elif level == 'ERROR':
        logging.error(f"[ALERT] {alert_message}")
    else:
        logging.debug(f"[ALERT] {alert_message}")

