
#!/usr/bin/env python3

import time
import unittest
import docker
import yaml
from time import sleep
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import warnings
import requests


## testing curl commands
#  > 2 different requests need to be made one after another
# curl -d 'app=test_service_local&access_key=test_secret_http' http://localhost:8080/step-1 -v
# curl -d 'app=test_service_local&access_key=test_secret_https' https://localhost:8443/step-2 -v -k
# curl -d 'app=test_service_nonlocal&access_key=test_secret_http' http://localhost:8080/step-1 -v
# curl -d 'app=test_service_nonlocal&access_key=test_secret_https' https://localhost:8443/step-2 -v -k

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Suppress InsecureRequestWarning
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        cls.client = docker.from_env()
        cls.container = cls.client.containers.get('port-knock-server')

        # Set default policies
        # current working directory need to be in the repo root because we're testing also session_cache.json file which in repo root
        with open('tests/config.test.yaml', 'r') as config_file:
            cls.config = yaml.safe_load(config_file)
        cls.test_service_local_port = cls.config['test_service_local']['port']
        cls.test_service_nonlocal_port = cls.config['test_service_nonlocal']['port']
        cls.http_port = 8080
        cls.https_port = 8443

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_two_step_process_local(self):
        # Step 1: HTTP request (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'test_secret_http'},
                          timeout=1)

        # Step 2: HTTPS request
        response = requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                                 data={'app': 'test_service_local', 'access_key': 'test_secret_https'},
                                 verify=False,  # Disable SSL verification for testing
                                 timeout=5)
        self.assertEqual(response.status_code, 503)  # Expecting 503 as per the server logic

        # Check the session_cache.json file inside the container
        max_retries = 10
        retry_delay = 1  # seconds
        for _ in range(max_retries):
            exec_result = self.container.exec_run('cat /app/session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if '"command":' in sessions:
                break
            time.sleep(retry_delay)
        else:
            self.fail(f"Session not created after {max_retries} retries. Content: {sessions}")

        # Test accessibility of the configured service port
        response = requests.get(f'http://localhost:{self.test_service_local_port}', timeout=5)
        self.assertEqual(response.status_code, 200, f"Port {self.test_service_local_port} should be accessible after the two-step process")

        # Wait for the session to expire for the other tests to get clean environment
        with open('tests/config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        max_wait_time = config['test_service_local']['duration'] + 5
        start_time = time.time()

        while time.time() - start_time < max_wait_time:
            exec_result = self.container.exec_run('cat /app/session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if sessions.strip() == '[]':
                break
            time.sleep(1)

    def test_two_step_process_nonlocal(self):
        # Step 1: HTTP request (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}',
                          data={'app': 'test_service_nonlocal', 'access_key': 'test_secret_http'},
                          timeout=1)

        # Step 2: HTTPS request
        response = requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                                 data={'app': 'test_service_nonlocal', 'access_key': 'test_secret_https'},
                                 verify=False,  # Disable SSL verification for testing
                                 timeout=5)
        self.assertEqual(response.status_code, 503)  # Expecting 503 as per the server logic

        # Check the session_cache.json file inside the container
        max_retries = 10
        retry_delay = 1  # seconds
        for _ in range(max_retries):
            exec_result = self.container.exec_run('cat /app/session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if '"command":' in sessions:
                break
            time.sleep(retry_delay)
        else:
            self.fail(f"Session not created after {max_retries} retries. Content: {sessions}")

        # Test accessibility of the configured service port
        response = requests.get(f'http://localhost:{self.test_service_nonlocal_port}', timeout=5)
        self.assertEqual(response.status_code, 200, f"Port {self.test_service_nonlocal_port} should be accessible after the two-step process")

        # Wait for the session to expire for the other tests to get clean environment
        with open('tests/config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        max_wait_time = config['test_service_nonlocal']['duration'] + 5
        start_time = time.time()

        while time.time() - start_time < max_wait_time:
            exec_result = self.container.exec_run('cat /app/session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if sessions.strip() == '[]':
                break
            time.sleep(1)

    def test_session_expiration(self):
        # Perform the two-step process
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'test_secret_http'},
                          timeout=1)

        requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                      data={'app': 'test_service_local', 'access_key': 'test_secret_https'},
                      verify=False,
                      timeout=5)

        # Wait for the session to expire
        with open('tests/config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        max_wait_time = config['test_service_local']['duration'] + 5
        start_time = time.time()

        while time.time() - start_time < max_wait_time:
            exec_result = self.container.exec_run('cat /app/session_cache.json')
            sessions = exec_result.output.decode('utf-8')
            if sessions.strip() == '[]':
                break
            time.sleep(1)

        self.assertEqual(sessions.strip(), '[]', "Session should be expired and removed from the cache")

        if time.time() - start_time >= max_wait_time:
            self.fail("Session did not expire within the maximum wait time")

        time.sleep(1)
        # Verify that the port is no longer accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_local_port}', timeout=1)

    def test_default_drop_local(self):
        # Test that the port is not accessible by default
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_local_port}', timeout=1)

    def test_default_drop_nonlocal(self):
        # Test that the port is not accessible by default
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_nonlocal_port}', timeout=1)

    def test_invalid_access_key(self):
        # HTTP request with invalid key (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'invalidkey'},
                          timeout=1)

        # Verify that the HTTPS port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'test_secret_https'},
                          verify=False,
                          timeout=1)

        # Verify that the service port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_local_port}', timeout=1)

    def test_invalid_app_name(self):
        # HTTP request with invalid app name (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}',
                          data={'app': 'invalidapp', 'access_key': 'test_secret_http'},
                          timeout=1)

        # Verify that the HTTPS port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'test_secret_https'},
                          verify=False,
                          timeout=1)

        # Verify that the service port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_local_port}', timeout=1)

    def test_missing_data(self):
        # HTTP request with missing data (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}', data={}, timeout=1)

        # Verify that the HTTPS port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'test_secret_https'},
                          verify=False,
                          timeout=1)

        # Verify that the service port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_local_port}', timeout=1)

    def test_http_get_request(self):
        # HTTP GET request (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.get(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}', timeout=1)

    def test_connection_timeout_get(self):
        # Test connection timeout for GET request
        start_time = time.time()
        with self.assertRaises(requests.exceptions.ReadTimeout):
            requests.get(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}', timeout=5)
        end_time = time.time()
        duration = end_time - start_time
        self.assertGreater(duration, 5)
        self.assertLess(duration, 6)  # Add a small buffer for overhead

    def test_connection_timeout_post(self):
        # Test connection timeout for POST request
        start_time = time.time()
        with self.assertRaises(requests.exceptions.ReadTimeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}', timeout=5)
        end_time = time.time()
        duration = end_time - start_time
        self.assertGreater(duration, 5)
        self.assertLess(duration, 6)  # Add a small buffer for overhead

    def test_valid_http_invalid_https_app_name(self):
        # Valid HTTP request (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'test_secret_http'},
                          timeout=1)

        # Invalid HTTPS request (invalid app_name)
        response = requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                                 data={'app': 'invalid_app', 'access_key': 'test_secret_https'},
                                 verify=False,
                                 timeout=5)
        self.assertEqual(response.status_code, 503)

        # Verify that the service port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_local_port}', timeout=1)
        time.sleep(5)

    def test_valid_http_invalid_https_access_key(self):
        # Valid HTTP request (should timeout)
        with self.assertRaises(requests.exceptions.Timeout):
            requests.post(f'http://localhost:{self.http_port}{self.config["global"]["http_post_path"]}',
                          data={'app': 'test_service_local', 'access_key': 'test_secret_http'},
                          timeout=1)

        # Invalid HTTPS request (invalid access_key)
        response = requests.post(f'https://localhost:{self.https_port}{self.config["global"]["https_post_path"]}',
                                 data={'app': 'test_service_local', 'access_key': 'invalid_key'},
                                 verify=False,
                                 timeout=5)
        self.assertEqual(response.status_code, 503)

        # Verify that the service port is not accessible
        with self.assertRaises((requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            requests.get(f'http://localhost:{self.test_service_local_port}', timeout=1)
        time.sleep(5)

if __name__ == "__main__":
    unittest.main()
