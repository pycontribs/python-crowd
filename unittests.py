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

    def testAuthUserInvalid(self):
        """User may not authenticate with invalid credentials"""
        result = self.crowd.auth_user('invaliduser', 'xxxxx')
        self.assertIs(result, None)

if __name__ == "__main__":
    unittest.main()
