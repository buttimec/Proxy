import socket
import ssl
import threading
import signal
from typing import Any, Tuple
import logging

import crypto
from config import app_config, Commands
from crypto import load_ca
from ctrl import CMD_VALUES
import chardet

from httpmsg import HTTP_PORT, PROTOCOL_SERVER_DELIMITER, \
    HEADER_SEPARATOR_BYTES, HEADER_SEPARATOR, HDR_CONNECTION, \
    HDR_PROXY_CONNECTION, HttpMsg, HTTPS_PORT

HDR_METHOD = 'method'
HDR_URL = 'url'
HDR_HOST = 'address'
HDR_HEADERS = 'headers'

DEFAULT_BUFFER_SIZE = 4096
DEFAULT_MAX_RECV_TRIES = 10
DEFAULT_SOCK_TIMEOUT = 0.1  # 100ms


class Server:
    """
    Proxy server

    Concepts: https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/
    """
    server_config: dict
    log_msgs: int
    recv_buffer_size: int
    max_recv_tries: int
    sock_timeout: float
    server_socket: socket.socket
    cmd_socket: socket.socket
    shutdown: bool = False
    https_mode: bool = False
    server_context: ssl.SSLContext = None
    client_context: ssl.SSLContext = None

    def __init__(self, config: dict):
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown_server)

        self.server_config = config
        self.set_logging(config)
        self.log_msgs = int(config.get('LOG_MSGS', 0))
        self.recv_buffer_size = config.get('MAX_REQUEST_LEN', DEFAULT_BUFFER_SIZE)
        self.max_recv_tries = config.get('MAX_RECV_TRIES', DEFAULT_MAX_RECV_TRIES)
        self.sock_timeout = config.get('CONNECTION_TIMEOUT', DEFAULT_SOCK_TIMEOUT)
        self.https_mode = config.get('MODE', 'https').lower() == 'https'
        self.ca_key, self.ca_cert = load_ca()

        self.__clients = {}     # key socket name, value shutdown flag
        self.__threads = {}
        self.__black_list = {}

        # SERVER_AUTH: context may be used to authenticate web servers i.e. it will be used to create client-side sockets
        self.client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Create command TCP socket
        self.cmd_socket = socket.create_server(
            ("", config['CMD_PORT']), family=socket.AF_INET,
            backlog=None, reuse_port=False)
        self.cmd_socket.settimeout(self.sock_timeout)

        # Create server TCP socket
        server_address = (config['HOST_NAME'], config['BIND_PORT'])
        self.server_socket = socket.create_server(
            server_address, family=socket.AF_INET,
            backlog=10, reuse_port=False)
        self.server_socket.settimeout(self.sock_timeout)

        self.__new_thread(name='main')

        # start the command thread
        d = threading.Thread(target=self.command_thread,
                             args=(self.cmd_socket,),
                             daemon=True)
        d.start()

        # start accepting requests
        self.info('', f"Started server on {server_address} in "
                      f"HTTP{'S' if self.https_mode else ''} mode")
        while not self.shutdown:
            try:
                if self.shutdown:
                    break
                # Establish the connection
                client_socket, client_address = self.server_socket.accept()

                self.info(client_address, "New connection")

                d = threading.Thread(#name=self._get_client_name(client_address),
                                     target=self.proxy_thread,
                                     args=(client_socket, client_address),
                                     daemon=True)
                d.start()
            except socket.timeout as e:
                pass

        # close all the sockets
        self.server_socket.close()
        self.shutdown_clients()
        self.close_socket(self.cmd_socket)

        self.info('', "Server shutdown")

    def shutdown_server(self, signum, frame):
        self.shutdown = True     # should really use a lock

    def _get_client_name(self, client_address: tuple):
        # Implement this method if needed
        return f'{client_address[0]}:{client_address[1]}'

    def proxy_thread(self, client_socket: socket.socket, client_address: tuple):
        """
        Handle a client connection
        :param client_socket: socket representing the client connection
        :param client_address: client address info, tuple of (hostaddr, port)
        """
        self.__new_thread()

        self.set_socket_timeout(client_socket)

        raw_request = self.recv(
            client_socket, 'client', buffer_size=self.recv_buffer_size,
            max_timeouts=self.max_recv_tries)

        if not raw_request:
            # nothing received, give up
            self.__del_thread()
            return

        # decode request
        request = self.decode_message(raw_request, client_address)

        self.info(client_address, f'Proxy request for {request.address}.')
        url = request.address[0]
        if any(substring in url for substring in self.__black_list):
            d = '<html><body><h1>403 Forbidden: This site is blocked</h1></body></html>'
            #error_response = f"HTTP/1.1 403 Forbidden\r\nContent-Length: {len(d)}\r\nContent-Type: text/html\r\n\r\n{d}"
            error_response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            client_socket.sendall(error_response.encode())
            print(f"Blocked request for {url} because it matches a blacklisted site substring.")
        else:
            self.handle_request(client_socket, request)
        self.__del_thread()

    def handle_request(
            self, client_socket: socket.socket, request: HttpMsg):

        client_name = client_socket.getsockname()
        msg = f'handle {request.method.upper()} request for {request.server}:{request.port} - keep-alive {request.is_keep_alive}'
        self.info(client_name, msg)

        try:
            # Create a new socket for the target server
            target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # target_socket is a client socket to the target
            target_socket = self.client_context.wrap_socket(
                target_socket, server_hostname=request.server)

            target_socket.connect(request.address)
            self.set_socket_timeout(target_socket)

            initial_msg = None  # initial msg to forward to target
            if request.is_connect:
                do_https = self.https_mode and request.is_https
                mitm_cert, mitm_key, mitm_context = (None, None, None) #Man In The Middle https://docs.mitmproxy.org/stable/concepts-howmitmproxyworks/

                if do_https:
                    mitm_cert, mitm_key, password = crypto.generate_cert(
                        request.address, self.ca_key, self.ca_cert
                    )
                    mitm_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    mitm_context.load_cert_chain(
                        certfile=mitm_cert, keyfile=mitm_key, password=password
                    )

                # Send a successful response to the client
                response = "HTTP/1.1 200 Connection established" + (HEADER_SEPARATOR * 2)
                self.send(client_socket, response, 'client')
                self.info(client_name, f'Connection established to {client_socket.getpeername()}')
                if do_https:
                    client_socket = mitm_context.wrap_socket(client_socket, server_side=True)


            else:
                initial_msg = request.raw

            self.add_client(client_name, [client_socket, target_socket])

            # Tunnel the traffic between the client and the target server
            self.tunnel(client_socket, target_socket, client_name,
                        keep_alive=request.is_keep_alive,
                        initial_msg=initial_msg,
                        buffer_size=self.recv_buffer_size)

        except ssl.SSLError as e:
            self.error('', f"SSL Error during HTTPS proxy handling: {e}")
        except socket.gaierror as e:
            self.error('', f"Socket GAIError during HTTPS proxy handling: {e}")
        except Exception as e:
            self.error('', f"Exception during HTTPS proxy handling: {e}")
        finally:
            self.info('', f"Finished handling: {msg}")
            self.del_client(client_name)

    def tunnel(self, client_socket: socket.socket, target_socket: socket.socket,
               name: str, keep_alive: bool = False, initial_msg: bytes = None,
               buffer_size: int = DEFAULT_BUFFER_SIZE):
        """
        Tunnel traffic between the client and the target server
        :param client_socket: socket representing the client connection
        :param target_socket: socket representing the target connection
        :param name: client name
        :param initial_msg: initial message to send to target; default None
        :param keep_alive: keep connection alive; default False
        :param buffer_size: buffer size
        """
        try:
            while not self.client_is_shutting(name):
                if initial_msg:
                    # forward initial msg to target
                    data = initial_msg
                    initial_msg = None
                else:
                    data = self.recv(
                        client_socket, 'client', buffer_size=buffer_size, max_timeouts=1)
                if data:
                    self.send(target_socket, data, 'target')

                data = self.recv(
                    target_socket, 'target', buffer_size=buffer_size, max_timeouts=1)
                if data:
                    self.send(client_socket, data, 'client')

                if not keep_alive:
                    break

        except ssl.SSLError as e:
            self.error('', f"SSL Error during tunneling: {e}")
        except socket.error as e:
            self.error('', f"Socket Error during tunneling: {e}")

    def recv(self, sock: socket.socket, source: str, buffer_size: int = DEFAULT_BUFFER_SIZE,
             max_timeouts: int = DEFAULT_MAX_RECV_TRIES) -> bytes:
        """
        Receive data
        :param sock: socket representing the connection
        :param source: source identifier
        :param buffer_size: buffer size
        :param max_timeouts: max times to try to receive after timeout
        """
        data = None
        source = f'from {source} ' if source else ''
        name = sock.getsockname()
        max_timeouts = 1 if max_timeouts <= 0 else max_timeouts
        #self.info(name, f'Recv max_timeouts {max_timeouts}')
        while max_timeouts:
            try:
                # get the request from browser
                data = sock.recv(buffer_size)
                if data:
                    self.info(name, f'Recv {source}{self.__data_msg(data)}')
                break
            except TimeoutError:
                max_timeouts -= 1
                if not data and not max_timeouts:
                    # nothing received, give up
                    self.debug(name, f'No data received {source}')

        return data

    def send(self, sock: socket.socket, data: bytes | str, where: str):
        """
        Send data
        :param sock: socket representing the connection
        :param data: data to send
        :param where: destination identifier
        """
        where = f'to {where} ' if where else ''
        if data:
            name = sock.getsockname()
            if isinstance(data, str):
                data = data.encode('utf-8')
            self.info(name, f'Send {where}{self.__data_msg(data)}')
            sock.sendall(data)

    def socket_wrap(self, sock: socket.socket, request: HttpMsg,
                    server_side: bool = False):

        if request.port == HTTPS_PORT and self.https_mode:
            if server_side:
                sock = self.server_context.wrap_socket(
                    sock, server_side=True)
            else:
                sock = self.client_context.wrap_socket(
                    sock, server_hostname=request.server)
        return sock

    def add_client(self, name: str, sock: socket.socket | list[socket.socket]):
        self.info('', f'New client {name}')
        self.__clients[name] = False

    def shutdown_clients(self):
        for name in self.__clients.keys():
            self.__clients[name] = True

    def client_is_shutting(self, name: str):
        shutting = False
        if name in self.__clients:
            shutting = self.__clients[name]
        return shutting

    def del_client(self, name: str):
        if name in self.__clients:
            # for sock, _ in self.__clients[name]:
            #     self.close_socket(sock)
            del self.__clients[name]

    def __data_msg(self, data: bytes):
        msg = f'{len(data)} B'
        if self.log_msgs != 0:
            msg_bytes = data[:self.log_msgs] if self.log_msgs > 0 else data
            msg = f'{msg} / {msg_bytes}'
            if len(data) > len(msg_bytes):
                msg = f'{msg}...'
        return msg

    def __new_thread(self, name: str = None):
        if not name:
            # default name is "Thread-N (target)", remove target from name
            name = threading.current_thread().name.split(' ')[0]
        threading.current_thread().name = name
        self.__threads[threading.get_ident()] = name

    def __del_thread(self):
        self.info('', "Thread closing")
        del self.__threads[threading.get_ident()]

    def set_socket_timeout(self, sock: socket.socket, timeout: float | None = -1):
        # https://docs.python.org/3/library/socket.html#socket.socket.settimeout
        # non-zero value - socket operations will raise a timeout exception if the timeout period value has elapsed before the operation has completed
        # zero - non-blocking mode
        # None - blocking mode
        if timeout is not None and timeout < 0:
            timeout = self.sock_timeout
        sock.settimeout(timeout)
        self.debug(sock.getsockname(),
                   f'blocking {sock.getblocking()} timeout {sock.gettimeout()}')

    @staticmethod
    def close_socket(sock: socket.socket):
        if sock and sock.fileno() > 0:
            # socket is still open, so close it
            # sock.shutdown(socket.SHUT_RDWR)
            sock.close()

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

    def decode_message(self, message: bytes, address: tuple) -> HttpMsg:
        """
        Decode a raw http message
        :param message: request bytes
        :param address: client address info, tuple of (hostaddr, port)
        :return: decoded request
        """
        request = HttpMsg(message)
        byte_lines = request.raw_headers.split(HEADER_SEPARATOR_BYTES)

        for idx, line in enumerate(byte_lines):
            # generally utf-8 but some can be windows_1252
            hdr_str = self.decode_bytes(line, 'utf-8', 'windows_1252')
            if hdr_str:
                hdr_str = hdr_str.strip().lower()     # process as lowercase
            if not hdr_str:
                if hdr_str is None:
                    self.error(address, f'Unable to decode header line {idx}: {line}')
                continue

            if idx == 0:
                # Parse the first line of the request to extract the target server and port
                line_splits = self._split_and_strip(hdr_str, ' ')
                if len(line_splits) < 2:
                    # http request will start with at least 2 items; e.g 'GET /index.html' or 'CONNECT server.example.com:80 HTTP/1.1'
                    self.error(address, f'Not a HTTP request: {line}')
                    # ignore since we don't know how to handle it
                    continue

                request.method = line_splits[0]
                request.url = line_splits[1]
                request.address = self.extract_target_server_and_port(request.url)
            else:
                # decode 'key: value'
                line_splits = self._split_and_strip(hdr_str, ':')
                if len(line_splits) < 2:
                    # header should have 2 items; e.g 'Connection: Keep-Alive'
                    self.error(address, f'Not a HTTP header: {line}')
                    # ignore since we don't know how to handle it
                    continue

                if line_splits[0] in [HDR_CONNECTION, HDR_PROXY_CONNECTION]:
                    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection
                    # 'close' or any comma-separated list of HTTP headers [Usually 'keep-alive' only]
                    value = self._split_and_strip(line_splits[1], ',')
                else:
                    value = line_splits[1]
                setattr(request, self.snake_case(line_splits[0]), value)

        return request

    @staticmethod
    def _split_and_strip(line: str, sep: str):
        line_splits = line.split(sep)
        return [ln.strip() for ln in line_splits]

    def command_thread(self, ctrl_socket: socket.socket):
        """
        Handle a client connection
        :param ctrl_socket: socket representing the command connection
        """
        self.__new_thread(name='command')

        self.info('', "Starting command server")

        controller_socket, ctrl_address, shutdown = (None, '', False)
        while not shutdown:
            # wait for connection
            while controller_socket is None:
                try:
                    # Establish the connection
                    controller_socket, ctrl_address = ctrl_socket.accept()

                    self.info(ctrl_address, "New command connection")
                except socket.timeout as e:
                    pass

            while not shutdown:
                # wait for command
                request = self.recv(
                    controller_socket, 'command',
                    buffer_size=self.server_config.get('MAX_REQUEST_LEN', DEFAULT_BUFFER_SIZE),
                    max_timeouts=1)

                if not request:
                    continue
                # process command
                request = request.decode('utf-8').strip().lower()
                if not request:
                    continue

                cmd_splits = request.split()
                cmd = cmd_splits[0]
                if cmd not in CMD_VALUES:
                    print(f'Unknown command: {cmd}')
                    continue
                if len(cmd_splits) > 1:
                    black = cmd_splits[1]
                response = None
                if cmd == Commands.CMD_SHUTDOWN.value:
                    shutdown = True
                    response = 'Shutdown initiated'
                elif cmd == Commands.LOG_MSGS.value:
                    response = f'Error: {cmd.upper()} x\n{" "*7}where x = -1:all data, 0:no data or >0:number of bytes'
                    if len(cmd_splits) >= 2:
                        try:
                            self.log_msgs = int(cmd_splits[1])
                            response = 'OK'
                        except ValueError:
                            pass
                elif cmd == Commands.BLACKLIST.value:
                    if len(self.__black_list) > 0:
                        response = str(self.__black_list)
                    else:
                        response = 'Blacklist Empty'
                elif cmd == Commands.NEW_BLACK.value:
                    self.__black_list.add(black)
                    response = 'Added to Blacklist'

                elif cmd == Commands.DEL_BLACK.value:
                    if(black in self.__black_list):
                        self.__black_list.remove(black)
                        response = 'Removed from Blacklist'
                    else:
                        response = 'Not in Blacklist'
                else:
                    self.info(ctrl_address, f"Unknown command {request}")

                if response:
                    self.send(controller_socket, response, 'command')

                if shutdown:
                    self.shutdown_server(signal.SIGINT, None)

        controller_socket.shutdown(socket.SHUT_RDWR)
        controller_socket.close()

    AUTO_DECODE = 'auto'

    def decode_bytes(self, request: bytes, *args) -> str:
        """
        Decode a request from bytes
        :param request: request to decode
        :param args: list of codecs to try to decode with
        :return: decoded string or None
        """
        decoded = None
        codecs_to_try = list(args)
        codecs_to_try.append(self.AUTO_DECODE)
        for codec in codecs_to_try:
            if codec == self.AUTO_DECODE:
                # https://chardet.readthedocs.io/en/latest/usage.html#basic-usage
                encoding = chardet.detect(request)
                # chardet uses normal codec name with spaces replaced by '-',
                # but python codec aliases are in snake case
                self.info('', f'Detected encoding: {encoding}')
                codec = self.snake_case(encoding['encoding'])
            try:
                decoded = request.decode(codec)
                break
            except UnicodeDecodeError as e:
                self.info('', f'UnicodeDecodeError: {e}')

        return decoded

    def snake_case(self, value: str) -> str:
        return value.lower() \
                .replace('-', '_') \
                .replace(' ', '_')


    def set_logging(self, config: dict):
        # https://docs.python.org/3/howto/logging.html
        enabled = config.get('LOGGING', False)
        if not enabled:
            level = logging.CRITICAL
        else:
            level = config.get('LOG_LEVEL', 'info')
            level = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
        logging.basicConfig(encoding='utf-8', level=level)

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


if __name__ == "__main__":

    server = Server(app_config)
