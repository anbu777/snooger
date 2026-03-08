import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from colorama import Fore, Style, init

init(autoreset=True)

class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, '')
        record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
        return super().format(record)

def setup_logger(workspace_dir, phase=None):
    log_name = f'snooger.{phase}' if phase else 'snooger'
    logger = logging.getLogger(log_name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    # Per-phase log file
    log_filename = f'{phase}.log' if phase else 'snooger.log'
    log_file = os.path.join(workspace_dir, log_filename)
    fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    fh.setFormatter(file_fmt)

    # Console handler with color
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(ColorFormatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

def get_logger(name='snooger'):
    return logging.getLogger(name)
