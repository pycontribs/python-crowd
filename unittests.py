import unittest
import crowd
import crowdserverstub
import json, requests, threading
import random

PORT = random.randint(8000, 8020)
APP_USER = 'testapp'
APP_PASS = 'testpass'

class testCrowdAuth(unittest.TestCase):
    """Test Crowd authentication"""

    def setUp(self):
        self.base_url = 'http://localhost:%d' % PORT
        self.crowd = crowd.CrowdServer(self.base_url, APP_USER, APP_PASS)

        self.server_thread = threading.Thread(
            target=crowdserverstub.run_server, args=(PORT,))
        self.server_thread.start()

        crowdserverstub.add_app(APP_USER, APP_PASS)

    def tearDown(self):
        requests.get(self.base_url + '/terminate')
        self.server_thread.join()

    def testAuthAppValid(self):
        """Application may authenticate with valid credentials"""
        result = self.crowd.auth_ping()
        self.assertEquals(result, True)

    def testAuthAppInvalid(self):
        """Application may not authenticate with invalid credentials"""
        c = crowd.CrowdServer(self.base_url, 'invaliduser', 'xxxxx')
        result = c.auth_ping()
        self.assertEquals(result, False)

if __name__ == "__main__":
    unittest.main()
