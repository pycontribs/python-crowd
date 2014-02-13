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
USER     = 'user1'
PASS     = 'pass1'
GROUP    = 'group1'


class testCrowdAuth(unittest.TestCase):
    """Test Crowd authentication"""

    @classmethod
    def setUpClass(cls):
        cls.base_url = 'http://localhost:%d' % PORT
        cls.crowd = crowd.CrowdServer(cls.base_url, APP_USER, APP_PASS)

        cls.server_thread = threading.Thread(
            target=crowdserverstub.run_server, args=(PORT,))
        cls.server_thread.start()

        crowdserverstub.add_app(APP_USER, APP_PASS)
        crowdserverstub.add_user(USER, PASS)

        # There is a race to start the HTTP server before
        # the unit tests begin hitting it. Sleep briefly
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        requests.get(cls.base_url + '/terminate')
        cls.server_thread.join()

    def testStubUserExists(self):
        """Check that server stub recognises user"""
        result = crowdserverstub.user_exists(USER)
        self.assertTrue(result)

    def testStubUserDoesNotExist(self):
        """Check that server stub does not know invalid user"""
        result = crowdserverstub.user_exists('fakeuser')
        self.assertFalse(result)

    def testStubCheckUserAuth(self):
        """Check that server stub auths our user/pass combination"""
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
        result = self.crowd.auth_user('invaliduser', 'xxxxx')
        self.assertIs(result, None)

    def testAuthUserInvalidPass(self):
        """User may not authenticate with invalid password"""
        result = self.crowd.auth_user(USER, 'xxxxx')
        self.assertIs(result, None)

    def testCreateSessionValidUser(self):
        """User may create a session with valid credentials"""
        result = self.crowd.get_session(USER, PASS)
        self.assertIsInstance(result, dict)

    def testCreateSessionInvalidUser(self):
        """User may not create a session with invalid username"""
        result = self.crowd.get_session('invaliduser', 'xxxxx')
        self.assertIs(result, None)

    def testCreateSessionInvalidPass(self):
        """User may not create a session with invalid password"""
        result = self.crowd.get_session(USER, 'xxxxx')
        self.assertIs(result, None)

    def testValidateSessionValidUser(self):
        """Validate a valid session token"""
        session = self.crowd.get_session(USER, PASS)
        token = session['token']
        result = self.crowd.validate_session(token)
        self.assertIsInstance(result, dict)

    def testValidateSessionInvalidToken(self):
        """Detect invalid session token"""
        token = '0' * 24
        result = self.crowd.validate_session(token)
        self.assertIs(result, None)

    def testValidateSessionValidUserUTF8(self):
        """Validate that the library handles UTF-8 in fields properly"""
        session = self.crowd.get_session(USER, PASS)
        token = session['token']
        result = self.crowd.validate_session(token)
        self.assertEquals(result['user']['email'], u'%s@does.not.ëxist' % USER)

    def testCreateSessionIdentical(self):
        """Sessions from same remote are identical"""
        session1 = self.crowd.get_session(USER, PASS, '192.168.99.99')
        session2 = self.crowd.get_session(USER, PASS, '192.168.99.99')
        self.assertEqual(session1, session2)

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
        self.assertIs(result, None)

    def testGetGroupsNotEmpty(self):
        crowdserverstub.add_user_to_group(USER, GROUP)
        result = self.crowd.get_groups(USER)
        self.assertEqual(set(result), set([GROUP]))
        crowdserverstub.remove_user_from_group(USER, GROUP)

    def testGetNestedGroupsNotEmpty(self):
        crowdserverstub.add_user_to_group(USER, GROUP)
        result = self.crowd.get_nested_groups(USER)
        self.assertEqual(set(result), set([GROUP]))
        crowdserverstub.remove_user_from_group(USER, GROUP)

    def testRemoveUserFromGroup(self):
        crowdserverstub.add_user_to_group(USER, GROUP)
        crowdserverstub.remove_user_from_group(USER, GROUP)
        result = self.crowd.get_groups(USER)
        self.assertEqual(set(result), set([]))

    def testGetNestedGroupUsersNotEmpty(self):
        crowdserverstub.add_user_to_group(USER, GROUP)
        result = self.crowd.get_nested_group_users(GROUP)
        self.assertEqual(set(result), set([USER]))
        crowdserverstub.remove_user_from_group(USER, GROUP)

    def testUserExists(self):
        result = self.crowd.user_exists(USER)
        self.assertTrue(result)

    def testUserAttributesExist(self):
        result = self.crowd.get_user(USER)
        self.assertIsNotNone(result)
        self.assertTrue('attributes' in result)

    def testUserAttributesReturned(self):
        crowdserverstub.add_user('attruser', 'mypass', {'something': True})
        result = self.crowd.get_user('attruser')
        self.assertIsNotNone(result)
        self.assertTrue('attributes' in result)
        self.assertTrue('something' in result['attributes'])

    def testUserCreationSuccess(self):
        result = self.crowd.add_user('newuser',
                                     email='me@test.example',
                                     password='hello')
        self.assertTrue(result)

    def testUserCreationDuplicate(self):
        result = self.crowd.add_user('newuser1',
                                     email='me@test.example',
                                     password='hello')
        self.assertTrue(result)
        result = self.crowd.add_user('newuser1',
                                     email='me@test.example',
                                     password='hello')
        self.assertFalse(result)

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
