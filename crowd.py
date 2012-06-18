import json
import requests
from urllib import urlencode

class CrowdServer(object):
    """Crowd server authentication object"""

    def __init__(self, crowd_url, app_name, app_pass):
        self.crowd_url = crowd_url
        self.app_name = app_name
        self.app_pass = app_pass
        self.rest_url = crowd_url.rstrip("/") + "/rest/usermanagement/1"

        self.auth_info = requests.auth.HTTPBasicAuth(app_name, app_pass)
        self.request_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def __str__(self):
        return "Crowd Server at %s" % self.crowd_url

    def __repr__(self):
        return "<CrowdServer('%s', '%s', %s')>" % (self.crowd_url, self.app_name, self.app_pass)

    def _get(self, url):
        req = requests.get(url, auth=self.auth_info,
            headers=self.request_headers)
        return req

    def _post(self, url, post_data):
        req = requests.post(url, data=json.dumps(post_data), auth=self.auth_info,
            headers=self.request_headers)
        return req

    def auth_ping(self):
        """Test that we can authenticate this application to Crowd"""

        url = self.rest_url + "/non-existent/location"
        response = self._get(url)

        if response.status_code == 401:
            # and response.text.startswith("Application failed to authenticate"):
            return False
        elif response.status_code == 404:
            return True
        else:
            # An error encountered - problem with the Crowd server?
            return False

    def auth_user(self, username, password):
        """Authenticate a user/password pair against the Crowd server"""

        url = self.rest_url + "/authentication?%s" % urlencode(
            {"username": username})
        response = self._post(url, {"value": password})

        # If authentication failed for any reason return None
        if not response.ok:
            return None

        # ...otherwise return a dictionary of user attributes
        return json.loads(response.text)

    def get_session(self, username, password, remote="127.0.0.1"):
        """Create a session for a user"""

        params = {
            "username" : username,
            "password" : password,
            "validation-factors": {
                "validationFactors": [
                    { "name": "remote_address", "value": remote, }
                ]
            }
        }

        url = self.rest_url + "/session"
        response = self._post(url, params)

        # If authentication failed for any reason return None
        if not response.ok:
            return None

        # Otherwise return the user object
        ob = json.loads(response.text)
        return ob

    def validate_session(self, token, remote="127.0.0.1"):
        """Validate a session token"""
        
        params = {
           "validationFactors" : [
              { "name": "remote_address", "value": remote, }
           ]
        }

        url = self.rest_url + "/session/%s?expand=user" % token
        response = self._post(url, params)

        # For consistency between methods use None rather than False
        # If token validation failed for any reason return None
        if not response.ok:
            return None

        # Otherwise return the user object
        ob = json.loads(response.text)
        return ob
