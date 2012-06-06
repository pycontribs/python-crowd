import re, sys
import BaseHTTPServer
from urllib2 import urlparse

httpd = None

class CrowdServerStub(BaseHTTPServer.BaseHTTPRequestHandler):

    def _default_handler(self):
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("Code: 404\n");
        self.wfile.write("Sorry, location does not exist\n")

    def _do_terminate(self):
        # Mark server object for termination
        self.server.keep_running = False

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("Terminating\n")

    def do_GET(self):
        handlers = [
            ("^/terminate", self._do_terminate),

            # Default handler for unmatched requests
            ("", self._default_handler),
        ]

        path = urlparse.urlparse(self.path)[2]
        for regex, method in handlers:
            if re.search(regex, path):
                method()
                return

        # The default handler should've caught any unmatched request.
        # This code should not be reached.
        self.send_response(500)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write('Oops, should not be here for %s' % self.path)


def init_server(port):
    global httpd
    httpd = BaseHTTPServer.HTTPServer(("", port), CrowdServerStub)
    return httpd

def run_server(port):
    if not httpd:
        init_server(port)
    httpd.keep_running = True
    while httpd.keep_running:
        httpd.handle_request()

if __name__ == "__main__":
    run_server(8001)
