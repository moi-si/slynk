import contextvars
import logging

from .config import CONFIG

conn_id = contextvars.ContextVar('connection_id', default='?')
policy_ctx = contextvars.ContextVar('policy_ctx', default=None)
force_close = contextvars.ContextVar('force_close', default=False)

class CustomLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.conn_id = conn_id.get()

if CONFIG.get('log_file'):
    logging.basicConfig(
        format="%(asctime)s %(conn_id)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filemode='w',
        filename=CONFIG['log_file']
    )
else:
    logging.basicConfig(
    format="%(asctime)s %(conn_id)s %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logging.setLogRecordFactory(CustomLogRecord)
logger = logging.getLogger('Slynk')
logger.setLevel(CONFIG["log_level"])
