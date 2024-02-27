import enum

app_config = {
    'MAX_REQUEST_LEN': 1024 * 6,
    'CONNECTION_TIMEOUT': 0.05,  # 100ms
    'MAX_RECV_TRIES': 10,
    'HOST_NAME': 'localhost',
    'BIND_PORT': 12345,
    'CMD_PORT': 23456,
    'MODE': 'https',     # 'http'/'https'
    'LOGGING': True,
    'LOG_LEVEL': 'info',  # 'info'/'error'/'debug'
    'LOG_MSGS': 40,  # number of bytes of msgs sent/recv content to log; -1=all, 0=none or positive number of bytes
    'CACHE_MSGS': True
}


# commands
class Commands(enum.StrEnum):
    CMD_SHUTDOWN = 'shutdown'
    LOGGING = 'logging'
    LOG_MSGS = 'log_msgs'
    BLACKLIST = 'blacklist'
    NEW_BLACK = 'new_black'
    DEL_BLACK = 'del_black'
    TOGGLE_CACHE = 'CACHE'

    @staticmethod
    def values():
        return [c.value for c in Commands]

