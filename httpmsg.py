from http import HTTPMethod, HTTPStatus
from typing import Tuple, Optional

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
HDR_CONTENT_LENGTH = 'content-length'

COMMA_SEPERATED_HEADERS = [HDR_CONNECTION, HDR_PROXY_CONNECTION]

HEADER_SEPARATOR = '\r\n'
HEADER_END = HEADER_SEPARATOR * 2
HEADER_SEPARATOR_BYTES = HEADER_SEPARATOR.encode('utf-8')
HEADER_END_BYTES = HEADER_END.encode('utf-8')
HEADER_END_BYTES_LEN = len(HEADER_END_BYTES)
# https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
METHODS = [m.value.lower() for m in HTTPMethod]     # list of 'connect' etc.
METHODS_BYTES = [m.encode() for m in METHODS]
CONNECT = HTTPMethod.CONNECT.value.lower()

StrBytes = str | bytes


class HttpMsg:

    raw: bytes

    method: str
    target: str
    address: Tuple[str, int]

    status: Optional[HTTPStatus]
    status_text: str
    keep_alive: str

    def __init__(self, request: bytes):
        self.raw = request
        self.method = ''
        self.target = ''
        self.address = ('', HTTP_PORT)
        self.status = None
        self.keep_alive = ''

    @property
    def content_len(self) -> int:
        return getattr(self, self.snake_case(HDR_CONTENT_LENGTH),0)

    @property
    def is_message_complete(self) -> bool:
        return self.content_len == len(self.raw_body)

    @property
    def absolute_url(self) -> str:
        if self.target.startswith('http'):
            url = self.target
        else:
            address = self.extract_target_server_and_port(getattr(self, 'host'))
            url = f"http{'s' if address[1] == HTTPS_PORT else ''}://{address[0]}{self.target}"
        return url

    @property
    def raw_headers(self) -> bytes:
        size = self.raw_header_size
        return self.raw[:size] if size > 0 else b''

    @property
    def raw_header_size(self) -> int:
        #size of raw headers (including blank line)
        hdr_end = self.raw.find(HEADER_END_BYTES)
        return hdr_end + HEADER_END_BYTES_LEN if hdr_end > 0 else -1

    @property
    def raw_headers_list(self) -> list[bytes]:
        headers = self.raw_headers
        return [
            h.strip() for h in headers.split(HEADER_SEPARATOR_BYTES)
        ] if headers else []

    @property
    def raw_body(self) -> bytes:
        size = self.raw_header_size
        return self.raw[size:] if size > 0 else self.raw

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

    @property
    def is_request(self) -> bool:
        headers = self.raw_headers_list
        return self.is_request_line(headers[0]) if headers else False

    @staticmethod
    def is_request_line(header: StrBytes):
        value = False
        if header:
            # check request line starts with a method and 3 items - 'GET' /example.html HTTP/1.1
            if isinstance(header,str):
                sep = ' '
                methods = METHODS
            else:
                sep = b' '
                methods = METHODS_BYTES
            splits = header.lower().split(sep)
            if len(splits) == 3 and splits[0] in methods:
                value = tuple(splits)
        return value

    @property
    def is_response(self) -> bool:
        headers = self.raw_headers_list
        return self.is_status_line(headers[0]) if headers else False

    @staticmethod
    def is_status_line(header: StrBytes):
        value = False
        if header:
            # check status line starts with http and 3 items - 'HTTP/1.1 404 Not Found
            if isinstance(header,str):
                http_protocol = 'http/'
                sep = ' '
            else:
                http_protocol = b'http/'
                sep = b' '
            splits = header.lower().split(sep)
            if len(splits) >= 3 and splits[0].startswith(http_protocol) and splits[1].isdigit():
                value = splits[0], int(splits[1], sep.join(splits[2:]))
        return value

    @staticmethod
    def extract_target_server_and_port(url: str) -> Tuple[str, int]:
        # Extract the target server and port from the URL
        http_pos = url.find(PROTOCOL_SERVER_DELIMITER)
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos + len(PROTOCOL_SERVER_DELIMITER)):]

        # find the port pos (if any)
        port_pos = temp.find(":")
        # find end of web server
        webserver_pos = temp.find("/")
        if webserver_pos == -1:
            webserver_pos = len(temp)

        if port_pos == -1 or webserver_pos < port_pos:
            # Default port for HTTP
            return temp[:webserver_pos], HTTP_PORT
        else:
            # Specific port
            return temp[:port_pos], int((temp[(port_pos + 1):])[:webserver_pos - port_pos - 1])

    @staticmethod
    def http_status(status_code: int) -> HTTPStatus:
        codes = list(filter(lambda  s: s.value == status_code, HTTPStatus))
        if not codes:
            raise ValueError(f'Unkown status code {status_code}')
        return codes[0]

    @staticmethod
    def snake_case(value: str):
        return value.lower().replace('-', '_')

    def decode(self) -> 'HttpMsg':
        for idx, line in enumerate(self.raw_headers_list):
            if idx == 0:
                #first line of message should be request/status
                if not self.is_request_line(line) and not self.is_status_line(line):
                    break
                    #not a http request
            try:
                hdr_str = line.decode('utf-8')
            except UnicodeDecodeError as e:
                hdr_str = line.decode('windows_1252')
            hdr_str = hdr_str.strip()
            if not hdr_str:
                continue # ignore

            if idx == 0:
                #extract the server and port for request/status
                request_line = self.is_request_line(hdr_str)
                if request_line:
                    self.method = request_line[0]
                    self.target = request_line[1]
                    self.address = self.extract_target_server_and_port(self.target)
                else:
                    status_line = self.is_status_line(hdr_str)
                    self.status = self.http_status(status_line[1])
                    self.status_text = status_line[2]
            else:
                hdr_str = hdr_str.lower()
                splits = [x.strip() for x in hdr_str.split(':')]
                if len(splits) < 2:
                    continue
                if splits[0] in COMMA_SEPERATED_HEADERS:
                    value = [x.strip() for x in splits[1].split(',')]
                else:
                    value = splits[1]
                attribute_name = self.snake_case(splits[0])
                setattr(self, attribute_name, value)
