import logging
import os
import sys
from datetime import datetime

def setup_logger(workspace_dir):
    log_file = os.path.join(workspace_dir, 'snooger.log')
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger('snooger')