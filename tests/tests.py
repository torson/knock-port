
#!/usr/bin/env python3

import requests
import time
import unittest
import docker
import json
import yaml
from time import sleep
import subprocess
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

## testing curl commands
#  > 2 different requests need to be made one after another
# curl -d 'app=test_app&access_key=test_secret_http' http://localhost:8080 -v
# curl -d 'app=test_app&access_key=test_secret_https' https://localhost:8443/secure -v -k

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = docker.from_env()
        cls.container = cls.client.containers.get('port-knock-server')
        
        # Set default policies
        with open('config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        cls.test_app_port = config['test_app']['port']
        cls.http_port = 8080
        cls.https_port = 8443
        
    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_two_phase_process(self):
        # Phase 1: HTTP request (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}', 
                          data={'app': 'test_app', 'access_key': 'test_secret_http'}, 
                          timeout=1)
        
        # Phase 2: HTTPS request
        response = requests.post(f'https://localhost:{self.https_port}/secure', 
                                 data={'app': 'test_app', 'access_key': 'test_secret_https'}, 
                                 verify=False,  # Disable SSL verification for testing
                                 timeout=5)
        self.assertEqual(response.status_code, 503)  # Expecting 503 as per the server logic
        
        # Check the session_cache.json file inside the container
        max_retries = 10
        retry_delay = 1  # seconds
        for _ in range(max_retries):
            exec_result = self.container.exec_run('cat session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if '"command":' in sessions:
                break
            time.sleep(retry_delay)
        else:
            self.fail(f"Session not created after {max_retries} retries. Content: {sessions}")
        
        # Test accessibility of the configured service port
        response = requests.get(f'http://localhost:{self.test_app_port}', timeout=5)
        self.assertEqual(response.status_code, 200, f"Port {self.test_app_port} should be accessible after the two-phase process")

    def test_session_expiration(self):
        # Perform the two-phase process
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}', 
                          data={'app': 'test_app', 'access_key': 'test_secret_http'}, 
                          timeout=1)
        
        requests.post(f'https://localhost:{self.https_port}/secure', 
                      data={'app': 'test_app', 'access_key': 'test_secret_https'}, 
                      verify=False, 
                      timeout=5)

        # Wait for the session to expire
        with open('config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        max_wait_time = config['test_app']['duration'] + 5
        start_time = time.time()
        
        while time.time() - start_time < max_wait_time:
            exec_result = self.container.exec_run('cat session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if sessions.strip() == '[]':
                break
            time.sleep(1)
        
        self.assertEqual(sessions.strip(), '[]', "Session should be expired and removed from the cache")
        
        if time.time() - start_time >= max_wait_time:
            self.fail("Session did not expire within the maximum wait time")

        # Verify that the port is no longer accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_app_port}', timeout=1)

    def test_default_drop(self):
        # Test that the port is not accessible by default
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_app_port}', timeout=1)

    def test_invalid_access_key(self):
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}', 
                          data={'app': 'test_app', 'access_key': 'invalidkey'}, 
                          timeout=1)
        
        response = requests.post(f'https://localhost:{self.https_port}/secure', 
                                 data={'app': 'test_app', 'access_key': 'invalidkey'}, 
                                 verify=False, 
                                 timeout=5)
        self.assertEqual(response.status_code, 503)

    def test_invalid_app_name(self):
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}', 
                          data={'app': 'invalidapp', 'access_key': 'test_secret_http'}, 
                          timeout=1)
        
        response = requests.post(f'https://localhost:{self.https_port}/secure', 
                                 data={'app': 'invalidapp', 'access_key': 'test_secret_https'}, 
                                 verify=False, 
                                 timeout=5)
        self.assertEqual(response.status_code, 503)

    def test_missing_data(self):
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}', data={}, timeout=1)
        
        response = requests.post(f'https://localhost:{self.https_port}/secure', 
                                 data={}, 
                                 verify=False, 
                                 timeout=5)
        self.assertEqual(response.status_code, 503)

    def test_get_request(self):
        response = requests.get(f'http://localhost:{self.http_port}', timeout=1)
        self.assertEqual(response.status_code, 404)

if __name__ == "__main__":
    unittest.main()
