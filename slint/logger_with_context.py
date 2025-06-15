import contextvars
import logging

from .config import CONFIG

client_port = contextvars.ContextVar('client_port', default='?')
domain_policy = contextvars.ContextVar('domain_policy', default=None)
remote_host = contextvars.ContextVar('remote_host', default=None)
# sni = contextvars.ContextVar('sni', default=None)

class CustomLogRecord(logging.LogRecord):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.c_port = client_port.get()

logging.basicConfig(
    format="%(asctime)s [%(c_port)s] %(levelname)-8s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.setLogRecordFactory(CustomLogRecord)
logger = logging.getLogger('Slint')
logger.setLevel(CONFIG["loglevel"])
