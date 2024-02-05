import socket
import threading
import signal

class Server:

    def __init__(self, config):
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown)

        # Create a TCP socket
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Re-use the socket
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # bind the socket to a public host, and a port
        self.serverSocket.bind((config['HOST_NAME'], config['BIND_PORT']))

        self.serverSocket.listen(10) # become a server socket
        self.__clients = {}

        print("Starting the server.")

        while True:

            # Establish the connection
            (clientSocket, client_address) = self.serverSocket.accept()

            d = threading.Thread(name=self._getClientName(client_address),
                                 target = self.proxy_thread, args=(clientSocket, client_address))
            d.setDaemon(True)
            d.start()

            # get the request from browser
            request = clientSocket.recv(config['MAX_REQUEST_LEN'])

            # parse the first line
            req_str = request.decode('utf8').replace('\r\n', '\n')
            first_line = req_str.split('\n')[0]

            print(f'Received request for {first_line}.')

            # get url
            url = first_line.split(' ')[1]

            print(f'Received request for {url}.')

            http_pos = url.find("://") # find pos of ://
            if (http_pos==-1):
                temp = url
            else:
                temp = url[(http_pos+3):] # get the rest of url

            port_pos = temp.find(":") # find the port pos (if any)

            # find end of web server
            webserver_pos = temp.find("/")
            if webserver_pos == -1:
                webserver_pos = len(temp)

            webserver = ""
            port = -1
            if (port_pos==-1 or webserver_pos < port_pos):

                # default port
                port = 80
                webserver = temp[:webserver_pos]

            else: # specific port
                port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
                webserver = temp[:port_pos]

            print(f'Forward request for {webserver} {port}.')

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(config['CONNECTION_TIMEOUT'])
            s.connect((webserver, port))
            s.sendall(request)

            while 1:
                # receive data from web server
                data = s.recv(config['MAX_REQUEST_LEN'])

                if (len(data) > 0):
                    clientSocket.send(data) # send to browser/client
                    print(f'Return responser {len(data)} bytes.')
                else:
                    s.close()
                    break

    def shutdown(self, signum, frame):
        print("Shutting down the server.")
        # Add any cleanup or shutdown logic here
        self.serverSocket.close()

    def _getClientName(self, client_address):
        # Implement this method if needed
        pass

    def proxy_thread(self, client_socket, client_address):
        # Implement this method if needed
        pass


if __name__ == "__main__":
    server = Server({
        'MAX_REQUEST_LEN': 1024*6,
        'CONNECTION_TIMEOUT': 15.0,
        'HOST_NAME': 'localhost',
        'BIND_PORT': 8080
    })

    while True:
        pass
