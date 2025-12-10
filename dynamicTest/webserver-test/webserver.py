#!/usr/bin/env python3
"""
Simple request-reflecting webserver.

- Listens on port 1389 by default.
- Prints every request it receives (request line, headers, and body) to stdout.
- Responds with the full URL that was requested (e.g. visiting http://localhost:1389/a returns the plain text "http://localhost:1389/a").

Usage:
    python3 reflect_server.py

Ctrl-C to stop.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.parse
import sys

PORT = 8083

class ReflectHandler(BaseHTTPRequestHandler):
    server_version = "ReflectHTTP/0.1"

    def _read_body(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        if length:
            return self.rfile.read(length)
        return b''

    def _print_request(self, body_bytes: bytes):
        # Print request line
        print('----- REQUEST START -----')
        print(f'{self.command} {self.path} {self.request_version}')
        # Print headers
        for name, value in self.headers.items():
            print(f'{name}: {value}')
        # Print body (if any)
        if body_bytes:
            try:
                text = body_bytes.decode('utf-8')
            except Exception:
                text = body_bytes.decode('latin-1', errors='replace')
            print('\n-- body (decoded) --')
            print(text)
        print('----- REQUEST END -------\n', flush=True)

    def _compose_url(self):
        # Prefer Host header to rebuild the full URL
        host = self.headers.get('Host')
        if not host:
            # fall back to the server socket address
            host = f"{self.server.server_address[0]}:{self.server.server_address[1]}"
        # assume http (not TLS) since this server is plain HTTP
        return f"http://{host}{self.path}"

    def _handle_all(self):
        body = self._read_body()
        self._print_request(body)

        url = self._compose_url()
        response_bytes = url.encode('utf-8')

        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()

        # HEAD should not send body
        if self.command != 'HEAD':
            self.wfile.write(response_bytes)

    # Handle common HTTP methods by delegating to _handle_all
    def do_GET(self):
        self._handle_all()

    def do_POST(self):
        self._handle_all()

    def do_PUT(self):
        self._handle_all()

    def do_DELETE(self):
        self._handle_all()

    def do_HEAD(self):
        self._handle_all()

    def do_OPTIONS(self):
        self._handle_all()

    def log_message(self, format, *args):
        # override default logging to keep output concise — we already print request details
        return

if __name__ == '__main__':
    server_address = ('', PORT)
    httpd = ThreadingHTTPServer(server_address, ReflectHandler)
    sa = httpd.socket.getsockname()
    print(f"Reflecting HTTP server listening on {sa[0]}:{sa[1]} (port {PORT}).")
    print("Send requests (GET/POST/PUT/DELETE/etc.) — each will be printed and replied with the requested URL.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('\nKeyboard interrupt received, shutting down server.')
        httpd.shutdown()
        httpd.server_close()
        sys.exit(0)

