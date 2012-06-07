import re, sys
import BaseHTTPServer
from urllib2 import urlparse

# Supported HTTP methods
GET    = 1
POST   = 2
PUT    = 3
DELETE = 4

httpd = None

app_auth = {}
user_auth = {}

def add_app(app_name, app_pass):
    global app_auth
    app_auth[app_name] = app_pass

def remove_app(app_name):
    global app_auth
    try:
        del app_auth[app_name]
    except KeyError: pass

def check_app_auth(headers):
    """Authenticate an application from Authorization HTTP header"""
    import base64

    try:
        auth_header = headers["Authorization"]
    except KeyError:
        return False

    # Only handle HTTP Basic authentication
    m = re.match("Basic (\w+==)", auth_header)
    if not m:
        return False

    encoded = m.groups()[0]
    decoded = base64.decodestring(encoded)

    m = re.match("([^:]+):(.+)", decoded)
    if not m:
        # Invalid authorization format
        return False

    app_user, app_pass = m.groups()

    global app_auth
    try:
        if app_auth[app_user] == app_pass:
            return True
    except KeyError:
        # No such user, fall through
        pass

    return False

def add_user(username, password):
    global user_auth
    user_auth[username] = password

def remove_user(username):
    global user_auth
    try:
        del user_auth[username]
    except KeyError: pass

def check_user_auth(username, password):
    """Authenticate an application from Authorization HTTP header"""
    global user_auth
    try:
        if user_auth[username] == password:
            return True
    except KeyError:
        # No such user, fall through
        pass

    return False


class CrowdServerStub(BaseHTTPServer.BaseHTTPRequestHandler):

    # Disable logging of fulfilled requests
    def log_request(self, format, *args):
        return

    def _default_handler(self):
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("Sorry, location does not exist\n")

    def _do_app_failed_auth(self):
        self.send_response(401)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("Application failed to authenticate\n")

    def _do_terminate(self):
        # Mark server object for termination
        self.server.keep_running = False

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write("Terminating\n")

    def _do_COMMON(self, method):
        handlers = [
            {
                "url": "^/terminate",
                "action": self._do_terminate,
                "require_auth": False,
            },

            # Default handler for unmatched requests
            { "url": "", "action": self._default_handler },
        ]

        # an application may authenticate to the server
        app_authenticated = check_app_auth(self.headers)

        path = urlparse.urlparse(self.path)[2]
        for handler in handlers:
            if re.search(handler['url'], path):
                require_auth = True
                try: require_auth = handler['require_auth']
                except: pass

                # Allow API call to be handled if application
                # authenticated or no auth required
                if app_authenticated or not require_auth:
                    handler['action']()
                    return

        # An unhandled path was encountered. This may happen if
        # the application did not authenticate and could not
        # match a path that permitted anonymous access
        if not app_authenticated:
            self._do_app_failed_auth()
            return

        # The default handler should've caught any unmatched request.
        # This code should not be reached.
        self.send_response(500)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write('Oops, should not be here for %s' % self.path)

    def do_GET(self):
        self._do_COMMON(GET)

    def do_POST(self):
        self._do_COMMON(POST)

    def do_PUT(self):
        self._do_COMMON(PUT)

    def do_DELETE(self):
        self._do_COMMON(DELETE)


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
