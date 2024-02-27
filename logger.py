import logging
import threading
from typing import Any


class LoggerMixin:

    def __init__(self):
        self.__threads = {}

    def new_thread(self, name: str = None):
        if not name:
            # default name is "Thread-N (target)", remove target from name
            name = threading.current_thread().name.split(' ')[0]
        threading.current_thread().name = name
        self.__threads[threading.get_ident()] = name

    def del_thread(self):
        self.info('', "Thread closing")
        del self.__threads[threading.get_ident()]

    def set_logging(self, config: dict):
        # https://docs.python.org/3/howto/logging.html
        enabled = config.get('LOGGING', False)
        if not enabled:
            level = logging.CRITICAL
        else:
            level = config.get('LOG_LEVEL', 'info')
            level = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        logging.basicConfig(format='%(asctime)s %(message)s', encoding='utf-8', level=level)

    def info(self, address: Any, msg: str):
        self.__log(logging.INFO, address, msg)

    def error(self, address: Any, msg: str):
        self.__log(logging.ERROR, address, msg)

    def debug(self, address: Any, msg: str):
        self.__log(logging.DEBUG, address, msg)

    def __log(self, level: int, address: Any, msg: str):
        thread_id = threading.get_ident()
        thread = self.__threads[thread_id] if thread_id in self.__threads else f'{thread_id:<5}'
        logging.log(level, f'{len(self.__threads)}/{len(threading.enumerate())} {thread:<10} {address}: {msg}')
