import contextvars
import logging

from .config import CONFIG

client_port = contextvars.ContextVar('client_port', default='?')
policy_ctx = contextvars.ContextVar('policy_ctx', default=None)
force_close = contextvars.ContextVar('force_close', default=False)

class CustomLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.c_port = client_port.get()

logging.basicConfig(
    format="%(asctime)s [%(c_port)s] %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.setLogRecordFactory(CustomLogRecord)
logger = logging.getLogger('Slynk')
logger.setLevel(CONFIG["loglevel"])
