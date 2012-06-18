import unittest
import crowd
import crowdserverstub
import json, requests, threading
import random, time

PORT = random.randint(8000, 8020)
APP_USER = 'testapp'
APP_PASS = 'testpass'
USER     = 'user1'
PASS     = 'pass1'

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
        self.assertIs(result, True)

    def testStubUserExists(self):
        """Check that server stub does not know invalid user"""
        result = crowdserverstub.user_exists('fakeuser')
        self.assertIs(result, False)

    def testStubCheckUserAuth(self):
        """Check that server stub auths our user/pass combination"""
        result = crowdserverstub.check_user_auth(USER, PASS)
        self.assertEquals(result, True)

    def testAuthAppValid(self):
        """Application may authenticate with valid credentials"""
        result = self.crowd.auth_ping()
        self.assertEquals(result, True)

    def testAuthAppInvalid(self):
        """Application may not authenticate with invalid credentials"""
        c = crowd.CrowdServer(self.base_url, 'invalidapp', 'xxxxx')
        result = c.auth_ping()
        self.assertEquals(result, False)

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

if __name__ == "__main__":
    unittest.main()
