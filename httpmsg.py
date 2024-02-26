from http import HTTPMethod
from typing import Tuple

HTTP_PORT = 80
HTTPS_PORT = 443

PROTOCOL_SERVER_DELIMITER = "://"

# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
# https://www.rfc-editor.org/rfc/rfc9110#name-connection
HDR_CONNECTION = 'connection'
# https://www.rfc-editor.org/rfc/rfc9112#appendix-C.2.2
HDR_PROXY_CONNECTION = 'proxy-connection'
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive
HDR_KEEP_ALIVE = 'keep-alive'
# https://www.rfc-editor.org/rfc/rfc9110#field.te
HDR_TE = 'te'
# https://www.rfc-editor.org/rfc/rfc9112#section-6.1
HDR_TRANSFER_ENCODING = 'transfer-encoding'
# https://www.rfc-editor.org/rfc/rfc9110#field.upgrade
HDR_UPGRADE = 'upgrade'

HEADER_SEPARATOR = '\r\n'
HEADER_END = HEADER_SEPARATOR * 2
HEADER_SEPARATOR_BYTES = HEADER_SEPARATOR.encode('utf-8')
HEADER_END_BYTES = HEADER_END.encode('utf-8')
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
METHODS = [m.value.lower() for m in HTTPMethod]     # list of 'connect' etc.
CONNECT = HTTPMethod.CONNECT.value.lower()


class HttpMsg:

    raw: bytes

    method: str
    url: str
    address: Tuple[str, int]
    connection: list[str]
    proxy_connection: list[str]
    keep_alive: str

    def __init__(self, request: bytes):
        self.raw = request
        self.method = ''
        self.url = ''
        self.address = ('', HTTP_PORT)
        self.connection = []
        self.proxy_connection = []
        self.keep_alive = ''

    @property
    def raw_headers(self) -> bytes:
        return self.raw[:self.raw.find(HEADER_END_BYTES)]

    @property
    def raw_body(self) -> bytes:
        return self.raw[self.raw.find(HEADER_END_BYTES) + len(HEADER_END_BYTES):]

    @property
    def is_keep_alive(self) -> bool:
        # If the value sent is keep-alive, the connection is persistent and not closed, allowing for subsequent requests to the same server to be done.
        return HDR_KEEP_ALIVE in self.connection or HDR_KEEP_ALIVE in self.proxy_connection

    @property
    def is_connect(self) -> bool:
        return self.method.lower() == CONNECT

    @property
    def server(self) -> str:
        return self.address[0]

    @property
    def port(self) -> int:
        return self.address[1]

    @property
    def is_https(self) -> bool:
        return self.port == HTTPS_PORT