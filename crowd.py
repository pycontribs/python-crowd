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

import json
import requests
from urllib import urlencode


class CrowdServer(object):
    """Crowd server authentication object.

    This is a Crowd authentication class to be configured for a
    particular application (app_name) to authenticate users
    against a Crowd server (crowd_url).

    This module uses the Crowd JSON API for talking to Crowd.

    An application account must be configured in the Crowd server
    and permitted to authenticate users against one or more user
    directories prior to using this module.

    Please see the Crowd documentation for information about
    configuring additional applications to talk to Crowd.
    """

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

    def _delete(self, url):
        req = requests.delete(url, auth=self.auth_info, headers=self.request_headers)
        return req

    def auth_ping(self):
        """Test that application can authenticate to Crowd.

        Attempts to authentication the application user against
        the Crowd server. In order for user authentication to
        work, an application must be able to authenticate.

        Returns:
            bool:
                True if the application authentication succeeded.
        """

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
        """Authenticate a user account against the Crowd server.

        Attempts to authenticate the user against the Crowd server.

        Args:
            username: The account username.

            password: The account password.

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd documentation
                for the authoritative list of attributes.

            None: If authentication failed.
        """

        url = self.rest_url + "/authentication?%s" % urlencode(
            {"username": username})
        response = self._post(url, {"value": password})

        # If authentication failed for any reason return None
        if not response.ok:
            return None

        # ...otherwise return a dictionary of user attributes
        return json.loads(response.text)

    def get_session(self, username, password, remote="127.0.0.1"):
        """Create a session for a user.

        Attempts to create a user session on the Crowd server.

        Args:
            username: The account username.

            password: The account password.

            remote:
                The remote address of the user. This can be used
                to create multiple concurrent sessions for a user.
                The host you run this program may need to be configured
                in Crowd as a trusted proxy for this to work.

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd
                documentation for the authoritative list of attributes.

            None: If authentication failed.
        """

        params = {
            "username": username,
            "password": password,
            "validation-factors": {
                "validationFactors": [
                    {"name": "remote_address", "value": remote, }
                ]
            }
        }

        url = self.rest_url + "/session?expand=user"
        response = self._post(url, params)

        # If authentication failed for any reason return None
        if not response.ok:
            return None

        # Otherwise return the user object
        ob = json.loads(response.text)
        return ob

    def validate_session(self, token, remote="127.0.0.1"):
        """Validate a session token.

        Validate a previously acquired session token against the
        Crowd server. This may be a token provided by a user from
        a http cookie or by some other means.

        Args:
            token: The session token.

            remote: The remote address of the user.

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd
                documentation for the authoritative list of attributes.

            None: If authentication failed.
        """

        params = {
           "validationFactors": [
              {"name": "remote_address", "value": remote, }
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

    def terminate_session(self, token):
        """Terminates the session token, effectively logging out the user
        from all crowd-enabled services.

        Args:
            token: The session token.

        Returns:
            True: If session terminated

            None: If session termination failed
        """

        url = self.rest_url + "/session/%s" % token
        response = self._delete(url)

        # For consistency between methods use None rather than False
        # If token validation failed for any reason return None
        if not response.ok:
            return None

        # Otherwise return True
        return True

    def get_groups(self, username):
        """Retrieve list of group names that have <username> as a member.

        Returns:
            list:
                A list of strings of group names.
        """

        url = self.rest_url + "/user/group/direct?%s" % urlencode(
            {"username": username})
        response = self._get(url)

        if not response.ok:
            return None

        return [g['name'] for g in json.loads(response.text)['groups']]
