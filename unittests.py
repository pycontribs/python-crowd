import unittest
import crowd
import crowdserverstub
import json, requests, threading

PORT = 8000

class testCrowdAuth(unittest.TestCase):
    """Test Crowd authentication"""

    def setUp(self):
        self.base_url = 'http://localhost:%d' % PORT
        crowdserverstub.init_server(PORT)
        self.server_thread = threading.Thread(
            target=crowdserverstub.run_server, args=(PORT,))
        self.server_thread.start()

    def tearDown(self):
        requests.get(self.base_url + '/terminate')
        self.server_thread.join()

if __name__ == "__main__":
    unittest.main()
