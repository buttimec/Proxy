import signal
import socket

from config import app_config, Commands


CMD_VALUES = Commands.values()
CMD_NAMES = [c.upper() for c in CMD_VALUES]

class ServerCtrl:

    server_config = None
    sock: socket.socket

    DEFAULT_BUFFER_SIZE = 4096
    DEFAULT_MAX_RECV_TRIES = 10

    def __init__(self, config: dict):
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown)

        self.server_config = config

    def start(self):
        # Create a new socket for the target server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.connect((self.server_config['HOST_NAME'], self.server_config['CMD_PORT']))
        self.sock.settimeout(self.server_config['CONNECTION_TIMEOUT'])

        buffer_size = self.server_config.get('MAX_REQUEST_LEN', self.DEFAULT_BUFFER_SIZE)
        max_timeouts = self.server_config.get('MAX_RECV_TRIES', self.DEFAULT_MAX_RECV_TRIES)

        print('Command connection established')

        shutdown = False
        while not shutdown:
            user_ip = input('Cmd: ')
            user_ip = user_ip.strip()
            if not user_ip:
                continue

            cmd_splits = user_ip.lower().split()
            cmd = cmd_splits[0]
            if len(cmd_splits) > 1:
                black = cmd_splits[1]
            if cmd not in CMD_VALUES:
                print(f'Unknown command: {cmd}')
                print(f'Valid commands:\n{CMD_NAMES}\n')
                continue

            self.sock.sendall(user_ip.encode('utf-8'))

            max_timeouts = 1 if max_timeouts <= 0 else max_timeouts
            while max_timeouts:
                try:
                    # get the request from browser
                    data = self.sock.recv(buffer_size)
                    if data:
                        print(data.decode('utf-8'))
                        break
                except TimeoutError:
                    max_timeouts -= 1

            shutdown = cmd == Commands.CMD_SHUTDOWN.value

        self.shutdown(signal.SIGINT, None)

    def shutdown(self, signum, frame):
        if self.sock and self.sock.fileno() > 0:
            self.sock.close()


if __name__ == "__main__":

    ctrl = ServerCtrl(app_config)
    ctrl.start()
