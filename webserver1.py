import os
import socket
import io
import sys
from datetime import datetime
import time
import json
import signal
import errno


class SignalHandler:
    """
    Handles zombie processes by waiting for child to finish and notifies parent
    """
    def __grim_reaper(self, signum, frame):
        pid, status = os.wait()

    def handle_signal(self, signal_num):
        signal.signal(signal_num, self.__grim_reaper)


class WSGIServer:
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM
    request_queue_size = 10000

    def __init__(self, server_address):
        self.signal_handler = SignalHandler()
        self.listen_socket = socket.socket(
            self.address_family,
            self.socket_type
        )
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind(server_address)
        self.listen_socket.listen(self.request_queue_size)
        host, port = self.listen_socket.getsockname()[:2]

        self.server_name = socket.getfqdn(host)
        self.server_port = port
        self.header_set = []

        self.app = None
        self.client_connection = None
        self.request_data = None

    @classmethod
    def make_server(cls, server_address, app):
        server = cls(server_address)
        server.set_application(app)
        return server

    def set_application(self, app):
        self.app = app

    def parse_request(self, text):
        request_line = text.splitlines()[0].rstrip('\r\n')
        return request_line.split()

    def start_response(self, status, response_headers, exc_info=None):
        server_headers = [
            ('Date', str(datetime.utcnow())),
            ('Server', 'WSGIServer 0.2')
        ]
        self.header_set = [status, response_headers + server_headers]

    def finish_response(self, framework_response):
        try:
            status, response_headers = self.header_set
            response = f'HTTP/1.1 {status}\r\n'
            for header in response_headers:
                response += '{0}: {1}\r\n'.format(*header)
            response += '\r\n'
            for data in framework_response:
                response += data.decode('utf-8')
            print(f"RESPONSE\n{response.splitlines()}\n")
            response_bytes = response.encode()
            self.client_connection.sendall(response_bytes)
        finally:
            self.client_connection.close()

    def get_env(self, method, path):
        env = {}
        env['wsgi.version'] = (1, 0)
        env['wsgi.url_scheme'] = 'http'
        env['wsgi.input'] = io.StringIO(self.request_data)
        env['wsgi.errors'] = sys.stderr
        env['wsgi.multithread'] = False
        env['wsgi.multiprocess'] = False
        env['wsgi.run_once'] = False
        # Required CGI variables
        env['REQUEST_METHOD'] = method
        env['PATH_INFO'] = path
        env['SERVER_NAME'] = self.server_name
        env['SERVER_PORT'] = str(self.server_port)
        return env

    def handle_request(self):
        self.request_data = self.client_connection.recv(1024).decode('utf-8')
        method, path, version = self.parse_request(self.request_data)
        print(
            f"REQUEST:\n"
            f"{json.dumps({'Method': method, 'Path': path, 'HTTPVersion': version}, indent=1)}\n"
        )

        env = self.get_env(method, path)
        framework_response = self.app(env, self.start_response)
        self.finish_response(framework_response)
        # time.sleep(1)

    def serve_forever(self):
        listen_socket = self.listen_socket

        # Handle zombie processes
        self.signal_handler.handle_signal(signal.SIGCHLD)

        while True:
            try:
                self.client_connection, client_address = listen_socket.accept()
            except IOError as e:
                code, msg = e.args
                if code == errno.EINTR:
                    continue
                else:
                    raise
            pid = os.fork()
            if pid == 0:
                listen_socket.close()
                self.handle_request()
                self.client_connection.close()
                os._exit(0)  # noqa
            else:
                self.client_connection.close()


SERVER_ADDRESS = (HOST, PORT) = '', 8888

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Provide a WSGI application object as module:callable')
    app_path = sys.argv[1]
    module, application = app_path.split(':')
    module = __import__(module)
    application = getattr(module, application)
    httpd = WSGIServer.make_server(SERVER_ADDRESS, application)
    print(f'WSGIServer: Serving HTTP on port {PORT} ...\n')
    httpd.serve_forever()
