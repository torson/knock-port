
#!/usr/bin/env python3

import requests
import time
import unittest
import docker
import json
from time import sleep

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = docker.from_env()
        cls.container = cls.client.containers.get('port-knock-server')
        
        # Create nftables table and chain
        cls.container.exec_run('nft add table ip vyos_filter')
        cls.container.exec_run("nft add chain ip vyos_filter NAME_IN-test_app-KnockPort '{ type filter hook input priority filter; policy accept; }'")
        
        print("nftables table and chain created")
        print("Container logs:")
        print(cls.container.logs().decode('utf-8'))

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_session_creation(self):
        response = requests.post('http://localhost:8080', data={'app': 'test_app', 'access_key': 'test_secret'})
        self.assertEqual(response.status_code, 503)
        
        # Check the session_cache.json file inside the container with retries
        max_retries = 5
        retry_delay = 1  # seconds
        for _ in range(max_retries):
            exec_result = self.container.exec_run('cat session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if '"command":' in sessions:
                break
            time.sleep(retry_delay)
        else:
            self.fail(f"Session not created after {max_retries} retries. Content: {sessions}")

    def test_session_expiration(self):
        response = requests.post('http://localhost:8080', data={'app': 'test_app', 'access_key': 'test_secret'})
        self.assertEqual(response.status_code, 503)
        
        time.sleep(15)

        exec_result = self.container.exec_run('cat session_cache.json')
        sessions = exec_result.output.decode('utf-8')
        self.assertEqual(sessions.strip(), '[]', "Session should be expired and removed from the cache")

    def test_invalid_access_key(self):
        response = requests.post('http://localhost:8080', data={'app': 'test_app', 'access_key': 'invalidkey'})
        self.assertEqual(response.status_code, 503)

    def test_invalid_app_name(self):
        response = requests.post('http://localhost:8080', data={'app': 'invalidapp', 'access_key': 'test_secret'})
        self.assertEqual(response.status_code, 503)

    def test_missing_data(self):
        response = requests.post('http://localhost:8080', data={})
        self.assertEqual(response.status_code, 503)

    def test_get_request(self):
        response = requests.get('http://localhost:8080')
        self.assertEqual(response.status_code, 404)

if __name__ == "__main__":
    unittest.main()
