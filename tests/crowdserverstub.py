# vim: set fileencoding=utf-8 :
# Copyright 2012 Alexander Else <aelse@else.id.au>.
#
# This file is part of the python-crowd library.
#
# python-crowd is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-crowd is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with python-crowd.  If not, see <http://www.gnu.org/licenses/>.

import re, sys

try:
    from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler  # Py27
except ImportError:
    from http.server import HTTPServer, BaseHTTPRequestHandler  # Py3k

try:
    from urllib2 import urlparse  # Py27
except ImportError:
    from urllib import parse as urlparse  # Py3k

import json

httpd = None

app_auth = {}
user_auth = {}
user_attributes = {}
group_auth = {}
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

    encoded = m.groups()[0].encode('ascii')
    decoded = base64.decodestring(encoded).decode('ascii')

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

def add_user_to_group(username, group):
    global group_auth
    if username not in group_auth:
        group_auth[username] = []
    if group not in group_auth[username]:
        group_auth[username].append(group)

def remove_user_from_group(username, group):
    global group_auth
    try:
        group_auth[username] = list(
            filter(lambda x: x != group, group_auth[username])
        )
    except KeyError: pass

def user_exists_in_group(username, group):
    """Check that user exists in a group"""
    global group_auth
    try:
        return group in group_auth[username]
    except:
        pass
    return False

def get_user_group_membership(username):
    """List of groups user is in"""
    global group_auth
    try:
        return group_auth[username]
    except:
        pass
    return []

def get_group_users(groupname):
    """List of users in the group"""
    global group_auth
    users = []
    for username, groups in group_auth.items():
        try:
            if groupname in groups:
                users.append(username)
        except:
            pass
    return users

def add_user(username, password, attributes=None):
    global user_auth
    global user_attributes
    user_auth[username] = password
    if attributes:
        user_attributes[username] = attributes

def remove_user(username):
    global user_auth
    try:
        del user_auth[username]
    except KeyError: pass

def get_user_attributes(username):
    try:
        attributes = user_attributes[username]
    except KeyError:
        attributes = {}
    return attributes

def user_exists(username):
    """Check that user exists"""
    global user_auth
    return (username in user_auth)

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
    token = hashlib.md5((username + remote).encode('utf-8')).hexdigest()[:24]
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
    del session_auth[token]

def build_user_dict(username):
    user_dict = {
        "name": username, "first-name": username,
        "last-name": username, "display-name": username,
        "email": u'%s@does.not.ëxist' % username, "active": True,
    }
    return user_dict


class CrowdServerStub(BaseHTTPRequestHandler):

    # Disable logging of fulfilled requests
    def log_request(self, format, *args):
        return

    def _default_handler(self):
        self.send_response(404)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Sorry, location does not exist\n".encode('ascii'))

    def _do_app_failed_auth(self):
        self.send_response(401)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Application failed to authenticate\n".encode('ascii'))

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
        self.wfile.write(json.dumps(response).encode('ascii'))

    def _do_terminate(self):
        # Mark server object for termination
        self.server.keep_running = False

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("Terminating\n".encode('ascii'))

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
        self.wfile.write(json.dumps(response).encode('ascii'))

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
        self.wfile.write(json.dumps(response).encode('ascii'))

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
        self.wfile.write(json.dumps(response).encode('ascii'))

    def _delete_session(self):
        m = re.search('/([A-Za-z\d]{24})', self.path)
        if m:
            token = m.groups()[0]

        response = {}
        response_code = 0

        if token:
            try:
                delete_session(token)
                response_code = 204
            except KeyError:
                response_code = 404
                response = {
                    "reason": "INVALID_SSO_TOKEN",
                    "message": "Token does not exist."
                }

        self.send_response(response_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('ascii'))

    def _get_groups(self):
        username = self.get_params['username'][0]
        groups = get_user_group_membership(username)
        response = {u'groups': [{u'name': x} for x in groups]}

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('ascii'))

    def _get_group_users(self):
        groupname = self.get_params['groupname'][0]
        users = get_group_users(groupname)
        response = {u'users': [{u'name': x} for x in users]}

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('ascii'))

    def _get_user(self):
        username = self.get_params['username'][0]
        if user_exists(username):
            response = {u'user': {u'name': username}}
            try:
                if self.get_params['expand'][0] == 'attributes':
                    response['attributes'] = get_user_attributes(username)
            except: pass
            self.send_response(200)
        else:
            response = {}
            self.send_response(404)

        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('ascii'))

    def _add_user(self):
        username = self.json_data['name']
        password = self.json_data['password']

        if not user_exists(username):
            add_user(username, password, attributes=self.json_data)
            self.send_response(201)
        else:
            response = {u'reason': u'INVALID_USER',
                        u'message': u'User already exists'}
            self.send_response(400)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('ascii'))

    def _do_COMMON(self, data={}):
        handlers = [
            {
                "url": r"/terminate",
                "action": self._do_terminate,
                "require_auth": False,
            },
            {
                "url": r"/rest/usermanagement/1/authentication$",
                "action": self._auth_user,
                "require_auth": True,
                "method": "POST",
            },
            {
                "url": r"/rest/usermanagement/1/session$",
                "action": self._get_session,
                "require_auth": True,
                "method": "POST",
            },
            {
                "url": r"/rest/usermanagement/1/session/[A-Za-z0-9]{24}$",
                "action": self._validate_session,
                "require_auth": True,
                "method": "POST",
            },
            {
                "url": r"/rest/usermanagement/1/session/[A-Za-z0-9]{24}$",
                "action": self._delete_session,
                "require_auth": True,
                "method": "DELETE",
            },
            {
                "url": r"/rest/usermanagement/1/user/group/direct$",
                "action": self._get_groups,
                "require_auth": True,
                "method": "GET",
            },
            {
                "url": r"/rest/usermanagement/1/user/group/nested$",
                "action": self._get_groups,
                "require_auth": True,
                "method": "GET",
            },
            {
                "url": r"/rest/usermanagement/1/group/user/nested$",
                "action": self._get_group_users,
                "require_auth": True,
                "method": "GET",
            },
            {
                "url": r"/rest/usermanagement/1/user$",
                "action": self._get_user,
                "require_auth": True,
                "method": "GET",
            },
            {
                "url": r"/rest/usermanagement/1/user$",
                "action": self._add_user,
                "require_auth": True,
                "method": "POST",
            },


            # Default handler for unmatched requests
            {
                "url": r".*",
                "action": self._default_handler,
                "require_auth": True,
            },
        ]

        p = urlparse.urlparse(self.path)

        self.json_data = data
        self.get_params = urlparse.parse_qs(p.query)

        for handler in handlers:
            method = handler.get('method')
            if (re.match(handler['url'], p.path)
                and (not method or method == self.command)):

                # Authenticate application if required
                require_auth = handler.get('require_auth')
                if require_auth and not check_app_auth(self.headers):
                    self._do_app_failed_auth()
                    return

                # Run the handler's action
                handler['action']()
                return

        # An unhandled path was encountered.
        self.send_response(500)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write('Oops, should not be here for {}'.format(self.path).encode('ascii'))

    def do_GET(self):
        self._do_COMMON()

    def do_POST(self):
        ct = self.headers.get('Content-Type')
        if ct != 'application/json':
            print("Received unwanted Content-Type (%s) in POST" % ct)

        cl = int(self.headers.get('Content-Length', 0))
        if cl > 0:
            data = self.rfile.read(cl).decode('utf-8')
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
    httpd = HTTPServer(("", port), CrowdServerStub)
    return httpd

def run_server(port):
    if not httpd:
        init_server(port)
    httpd.keep_running = True
    while httpd.keep_running:
        httpd.handle_request()

if __name__ == "__main__":
    run_server(8001)
