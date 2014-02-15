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

import sys
sys.path.append('..')

import unittest
import crowd
import crowdserverstub
import requests, threading
import random, time

PORT = random.randint(8000, 8020)
print("Port {0}".format(PORT))
APP_USER = 'testapp'
APP_PASS = 'testpass'
USER     = 'pythoncrowdtestuser'
PASS     = 'pass1'
EMAIL    = 'me@test.example'
GROUP    = 'pythoncrowdtestgroup'


class testCrowdAuth(unittest.TestCase):
    """Test Crowd authentication"""

    @classmethod
    def setUpClass(cls):
        import os
        if 'CROWDSERVER' in os.environ:
            cls.base_url = os.environ['CROWDSERVER']
            cls.server_thread = None
        else:
            cls.base_url = 'http://localhost:%d' % PORT
            cls.server_thread = threading.Thread(
                target=crowdserverstub.run_server, args=(PORT,))
            cls.server_thread.start()
            crowdserverstub.add_app(APP_USER, APP_PASS)
            # There is a race to start the HTTP server before
            # the unit tests begin hitting it. Sleep briefly
            time.sleep(0.2)

        cls.crowd = crowd.CrowdServer(cls.base_url, APP_USER, APP_PASS)

        # Create user account for most tests
        try:
            cls.crowd.add_user(USER, password=PASS, email=EMAIL)
        except crowd.CrowdUserExists:
            pass
        cls.num_users_created = 0
        try:
            cls.crowd.add_group(GROUP)
        except crowd.CrowdGroupExists:
            pass

    @classmethod
    def tearDownClass(cls):
        if cls.server_thread:
            requests.get(cls.base_url + '/terminate')
            cls.server_thread.join()
        else:
            # Remove users
            try:
                cls.crowd.remove_user(USER)
            except:
                pass
            for i in xrange(0, cls.num_users_created):
                try:
                    cls.crowd.remove_user(USER + str(i))
                except:
                    pass
            # Remove groups
            try:
                cls.crowd.remove_group(GROUP)
            except:
                pass

    def testStubUserExists(self):
        """Check that server stub recognises user"""
        if self.server_thread:
            result = crowdserverstub.user_exists(USER)
            self.assertTrue(result)

    def testStubUserDoesNotExist(self):
        """Check that server stub does not know invalid user"""
        if self.server_thread:
            result = crowdserverstub.user_exists('fakeuser')
            self.assertFalse(result)

    def testStubCheckUserAuth(self):
        """Check that server stub auths our user/pass combination"""
        if self.server_thread:
            result = crowdserverstub.check_user_auth(USER, PASS)
            self.assertTrue(result)

    def testCrowdObjectSSLVerifyTrue(self):
        """Check can create Crowd object with ssl_verify=True"""
        c = crowd.CrowdServer("http://bogus", APP_USER, APP_PASS, ssl_verify=True)
        self.assertIsInstance(c, crowd.CrowdServer)

    def testCrowdObjectSSLVerifyFalse(self):
        """Check can create Crowd object with ssl_verify=False"""
        c = crowd.CrowdServer("http://bogus", APP_USER, APP_PASS, ssl_verify=False)
        self.assertIsInstance(c, crowd.CrowdServer)

    def testAuthAppValid(self):
        """Application may authenticate with valid credentials"""
        result = self.crowd.auth_ping()
        self.assertTrue(result)

    def testAuthAppInvalid(self):
        """Application may not authenticate with invalid credentials"""
        c = crowd.CrowdServer(self.base_url, 'invalidapp', 'xxxxx')
        result = c.auth_ping()
        self.assertFalse(result)

    def testAuthUserValid(self):
        """User may authenticate with valid credentials"""
        result = self.crowd.auth_user(USER, PASS)
        self.assertIsInstance(result, dict)

    def testAuthUserInvalidUser(self):
        """User may not authenticate with invalid username"""
        with self.assertRaises(crowd.CrowdAuthFailure):
            result = self.crowd.auth_user('invaliduser', 'xxxxx')

    def testAuthUserInvalidPass(self):
        """User may not authenticate with invalid password"""
        with self.assertRaises(crowd.CrowdAuthFailure):
            result = self.crowd.auth_user(USER, 'xxxxx')

    def testCreateSessionValidUser(self):
        """User may create a session with valid credentials"""
        result = self.crowd.get_session(USER, PASS)
        self.assertIsInstance(result, dict)

    def testCreateSessionInvalidUser(self):
        """User may not create a session with invalid username"""
        def f():
            result = self.crowd.get_session('invaliduser', 'xxxxx')
        self.assertRaises(crowd.CrowdAuthFailure, f)

    def testCreateSessionInvalidPass(self):
        """User may not create a session with invalid password"""
        def f():
            result = self.crowd.get_session(USER, 'xxxxx')
        self.assertRaises(crowd.CrowdAuthFailure, f)

    def testValidateSessionValidUser(self):
        """Validate a valid session token"""
        session = self.crowd.get_session(USER, PASS)
        token = session['token']
        result = self.crowd.validate_session(token)
        self.assertIsInstance(result, dict)

    def testValidateSessionInvalidToken(self):
        """Detect invalid session token"""
        with self.assertRaises(crowd.CrowdAuthFailure):
            token = '0' * 24
            result = self.crowd.validate_session(token)

    def testValidateSessionValidUserUTF8(self):
        """Validate that the library handles UTF-8 in fields properly"""
        username = USER + "unicode"
        email = u'ÜñÍçÔÐê'
        try:
            self.crowd.add_user(username, password=PASS, email=email)
        except crowd.CrowdUserExists:
            pass
        session = self.crowd.get_session(username, PASS)
        token = session['token']
        result = self.crowd.validate_session(token)
        self.crowd.remove_user(username)
        self.assertEquals(result['user']['email'], email)

    def testCreateSessionIdentical(self):
        """Sessions from same remote are identical"""
        session1 = self.crowd.get_session(USER, PASS, '192.168.99.99')
        session2 = self.crowd.get_session(USER, PASS, '192.168.99.99')
        self.assertEqual(session1['token'], session2['token'])

    def testCreateSessionMultiple(self):
        """User may create multiple sessions from different remote"""
        session1 = self.crowd.get_session(USER, PASS, '192.168.99.99')
        session2 = self.crowd.get_session(USER, PASS, '192.168.88.88')
        self.assertNotEqual(session1, session2)

    def testTerminateSessionValidToken(self):
        """Terminate a valid session token"""
        session = self.crowd.get_session(USER, PASS)
        token = session['token']
        result = self.crowd.terminate_session(token)
        self.assertTrue(result)

    def testTerminateSessionInvalidToken(self):
        token = '0' * 24
        result = self.crowd.terminate_session(token)
        self.assertTrue(result)

    def testGetGroupsNotEmpty(self):
        self.crowd.add_user_to_group(USER, GROUP)
        result = self.crowd.get_groups(USER)
        self.assertEqual(set(result), set([GROUP]))
        self.crowd.remove_user_from_group(USER, GROUP)

    def testGetNestedGroupsNotEmpty(self):
        self.crowd.add_user_to_group(USER, GROUP)
        result = self.crowd.get_nested_groups(USER)
        self.crowd.remove_user_from_group(USER, GROUP)
        self.assertEqual(set(result), set([GROUP]))

    def testRemoveUserFromGroup(self):
        self.crowd.add_user_to_group(USER, GROUP)
        self.crowd.remove_user_from_group(USER, GROUP)
        result = self.crowd.get_groups(USER)
        self.assertEqual(set(result), set([]))

    def testGetNestedGroupUsersNotEmpty(self):
        self.crowd.add_user_to_group(USER, GROUP)
        result = self.crowd.get_nested_group_users(GROUP)
        self.crowd.remove_user_from_group(USER, GROUP)
        self.assertEqual(set(result), set([USER]))

    def testUserExists(self):
        result = self.crowd.user_exists(USER)
        self.assertTrue(result)

    def testUserAttributesExist(self):
        result = self.crowd.get_user(USER)
        self.assertIsNotNone(result)
        self.assertTrue('attributes' in result)

    def testUserAttributesReturned(self):
        result = self.crowd.get_user(USER)
        self.assertIsNotNone(result)
        self.assertTrue('attributes' in result)
        self.assertTrue('attributes' in result['attributes'])  # Yo dawg

    def testUserCreationSuccess(self):
        username = USER + "tmp"
        result = self.crowd.add_user(username, password=PASS, email=EMAIL)
        self.crowd.remove_user(username)
        self.assertTrue(result)

    def testUserCreationDuplicate(self):
        def add_user():
            result = self.crowd.add_user(USER, password=PASS, email=EMAIL)
            return result
        # USER already created during test setup
        self.assertRaises(crowd.CrowdUserExists, add_user)

    def testUserCreationMissingPassword(self):
        def f():
            result = self.crowd.add_user('newuser2',
                                         email='me@test.example')
        self.assertRaisesRegexp(ValueError, "missing password", f)

    def testUserCreationMissingEmail(self):
        def f():
            result = self.crowd.add_user('newuser',
                                         password='something')
        self.assertRaisesRegexp(ValueError, "missing email", f)

    def testUserCreationInvalidParam(self):
        def f():
            result = self.crowd.add_user('newuser',
                                         email='me@test.example',
                                         password='hello',
                                         invalid_param='bad argument')
        self.assertRaisesRegexp(ValueError, "invalid argument .*", f)

if __name__ == "__main__":
    unittest.main()
