import contextvars
import logging
import sys

from .config import CONFIG

conn_id = contextvars.ContextVar('connection_id', default='?')
policy_ctx = contextvars.ContextVar('policy_ctx', default=None)
force_close = contextvars.ContextVar('force_close', default=False)

class CustomLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.conn_id = conn_id.get()
logging.setLogRecordFactory(CustomLogRecord)

logger = logging.getLogger('Slynk')
logger.setLevel(logging.DEBUG)

LOG_FORMAT = "%(asctime)s %(conn_id)s %(levelname)-8s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(CONFIG.get('console_log_level') or logging.INFO)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

if CONFIG.get('log_file'):
    file_handler = logging.FileHandler(
        CONFIG['log_file'], mode='w', encoding='utf-8')
    file_handler.setLevel(CONFIG.get('file_log_level') or logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
