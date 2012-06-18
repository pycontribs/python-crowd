import re, sys
import BaseHTTPServer
from urllib2 import urlparse
import json

httpd = None

app_auth = {}
user_auth = {}
session_auth = {}

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

def user_exists(username):
    """Check that user exists"""
    global user_auth
    return user_auth.has_key(username)

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

def create_session(username, remote):
    """Create a user session for an authenticated user"""
    import hashlib
    global session_auth
    token = hashlib.md5(username + remote).hexdigest()[:24]
    session_auth[token] = { "username": username, "remote": remote, }
    return token

def validate_session(token, remote):
    """Validate a user session"""
    global session_auth

    session = None
    try: session = session_auth[token]
    except KeyError: pass

    # Unknown session token
    if not session:
        return None

    # Check any validation factors (just remote now)
    if session["remote"] != remote:
        return None

    # User has authenticated, return a session object
    response = {
        "token": token,
        "user": build_user_dict(session["username"]),
    }
    return response

def delete_session(token):
    global session_auth
    try:
        del session_auth[token]
    except KeyError: pass

def build_user_dict(username):
    user_dict = {
        "name": username, "first-name": username,
        "last-name": username, "display-name": username,
        "email": '%s@does.not.exist' % username, "active": True,
    }
    return user_dict


class CrowdServerStub(BaseHTTPServer.BaseHTTPRequestHandler):

    # Disable logging of fulfilled requests
    def log_request(self, format, *args):
        return

    def _default_handler(self):
        self.send_response(404)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Sorry, location does not exist\n")

    def _do_app_failed_auth(self):
        self.send_response(401)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Application failed to authenticate\n")

    def _do_user_failed_auth(self, bad_user=False, bad_pass=False):
        response = {}

        if bad_user:
            response["reason"] = "USER_NOT_FOUND"
            response["message"] = "User <whatever> does not exist"

        if bad_pass:
            response["reason"] = "INVALID_USER_AUTHENTICATION"
            response["message"] = "Failed to authenticate principal, password was invalid" 
        self.send_response(400)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response))

    def _do_terminate(self):
        # Mark server object for termination
        self.server.keep_running = False

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Terminating\n")

    def _auth_user(self):
        username = self.get_params['username'][0]
        password = self.json_data['value']
        user_authenticated = check_user_auth(username, password)

        response = {}
        response_code = 0

        # Either user may authenticate, used an invalid password,
        # or user does not exist.
        if user_authenticated:
            response_code = 200
            response = build_user_dict(username)
        elif user_exists(username):
            response_code = 400
            response = {
                "reason": "INVALID_USER_AUTHENTICATION",
                "message": "Failed to authenticate principal, password was invalid",
            }
        else:
            response_code = 400
            response = {
                "reason": "USER_NOT_FOUND",
                "message": 'User <%s> does not exist' % username
            }

        self.send_response(response_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response))

    def _get_session(self):
        username = self.json_data['username']
        password = self.json_data['password']
        v_factor = self.json_data['validation-factors']['validationFactors']
        remote = ''
        for f in v_factor:
            if f['name'] == 'remote_address':
                remote = f['value']

        user_authenticated = check_user_auth(username, password)

        response = {}
        response_code = 0

        # Either user may authenticate, used an invalid password,
        # or user does not exist.
        if user_authenticated:
            response_code = 200
            token = create_session(username, remote)
            response = {
                "token": token,
                "user": build_user_dict(username),
            }
        elif user_exists(username):
            response_code = 400
            response = {
                "reason": "INVALID_USER_AUTHENTICATION",
                "message": "Failed to authenticate principal, password was invalid",
            }
        else:
            response_code = 400
            response = {
                "reason": "USER_NOT_FOUND",
                "message": 'User <%s> does not exist' % username
            }

        self.send_response(response_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response))

    def _validate_session(self):
        v_factor = self.json_data['validationFactors']
        remote = ''
        for f in v_factor:
            if f['name'] == 'remote_address':
                remote = f['value']

        token = None
        m = re.search('/([A-Za-z\d]{24})', self.path)
        if m:
            token = m.groups()[0]
            session = validate_session(token, remote)
        else:
            session = None

        response = {}
        response_code = 0

        if session:
            response_code = 200
            response = session
        else:
            response_code = 404
            response = {
                "reason": "INVALID_SSO_TOKEN",
                "message":"Token does not validate."
            }

        self.send_response(response_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response))

    def _do_COMMON(self, data={}):
        handlers = [
            {
                "url": "^/terminate",
                "action": self._do_terminate,
                "require_auth": False,
            },
            {
                "url": "/authentication",
                "action": self._auth_user,
                "require_auth": False,
                "method": "POST",
            },
            {
                "url": "/session$",
                "action": self._get_session,
                "require_auth": False,
                "method": "POST",
            },
            {
                "url": "/session/[A-Za-z0-9]{24}",
                "action": self._validate_session,
                "require_auth": False,
                "method": "POST",
            },

            # Default handler for unmatched requests
            { "url": "", "action": self._default_handler },
        ]

        # An application must authenticate to the server
        # except for the terminate instruction
        app_authenticated = check_app_auth(self.headers)
        p = urlparse.urlparse(self.path)

        if not app_authenticated and p.path != '/terminate':
            self._do_app_failed_auth()
            return

        self.json_data = data
        self.get_params = urlparse.parse_qs(p.query)

        for handler in handlers:
            if re.search(handler['url'], p.path):
                require_auth = True
                try: require_auth = handler['require_auth']
                except: pass
                method = None
                try: method = handler['method']
                except: pass

                # Allow API call to be handled if application
                # authenticated or no auth required
                if (app_authenticated or not require_auth) and (method == self.command or method == None):
                    #print 'running handler for %s (%s)' % (p.path, self.path)
                    handler['action']()
                    return

        # An unhandled path was encountered. This may happen if
        # the user did not authenticate and could not
        # match a path that permitted anonymous access
        #user_authenticated = check_user_auth(username, password)
        user_authenticated = None
        if not user_authenticated:
            self._do_user_failed_auth()
            return

        # The default handler should've caught any unmatched request.
        # This code should not be reached.
        self.send_response(500)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write('Oops, should not be here for %s' % self.path)

    def do_GET(self):
        self._do_COMMON()

    def do_POST(self):
        try: ct = self.headers['Content-Type']
        except KeyError: ct = 'unknown'
        if ct != 'application/json':
            print "Received unwanted Content-Type (%s) in POST" % ct

        try: cl = int(self.headers['Content-Length'])
        except KeyError: cl = 0

        if cl > 0:
            data = self.rfile.read(cl)
        else:
            data = ""

        jdata = json.loads(data)

        self._do_COMMON(data=jdata)

    def do_PUT(self):
        self._do_COMMON()

    def do_DELETE(self):
        self._do_COMMON()


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
