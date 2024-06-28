
import requests
import time
import json
import subprocess
import unittest

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server
        cls.server_process = subprocess.Popen(["python", "server.py", "--test"])
        time.sleep(2)  # Give the server time to start

    @classmethod
    def tearDownClass(cls):
        # Stop the server
        cls.server_process.terminate()
        cls.server_process.wait()

    def test_session_creation(self):
        response = requests.post('http://localhost:8080', data={'app': 'openvpn', 'access_key': 'secret123'})
        self.assertEqual(response.status_code, 503)
        
        with open('session_cache.json', 'r') as f:
            sessions = json.load(f)
        self.assertEqual(len(sessions), 1, "Session should be created")

    def test_session_expiration(self):
        response = requests.post('http://localhost:8080', data={'app': 'openvpn', 'access_key': 'secret123'})
        self.assertEqual(response.status_code, 503)
        
        time.sleep(15)

        with open('session_cache.json', 'r') as f:
            sessions = json.load(f)
        self.assertEqual(len(sessions), 0, "Session should be expired and removed from the cache")

    def test_invalid_access_key(self):
        response = requests.post('http://localhost:8080', data={'app': 'openvpn', 'access_key': 'invalidkey'})
        self.assertEqual(response.status_code, 503)

    def test_invalid_app_name(self):
        response = requests.post('http://localhost:8080', data={'app': 'invalidapp', 'access_key': 'secret123'})
        self.assertEqual(response.status_code, 503)

    def test_missing_data(self):
        response = requests.post('http://localhost:8080', data={})
        self.assertEqual(response.status_code, 400)

    def test_get_request(self):
        response = requests.get('http://localhost:8080')
        self.assertEqual(response.status_code, 404)

if __name__ == "__main__":
    unittest.main()
