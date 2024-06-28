
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

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = docker.from_env()
        cls.container = cls.client.containers.get('port-knock-server')
        
        # Create nftables table and chain
        cls.container.exec_run('nft add table ip input_test')
        cls.container.exec_run("nft add chain ip input_test in-knock-port '{ type filter hook input priority filter; policy accept; }'")
        
        # Set default policies
        with open('config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        cls.test_app_port = config['test_app']['port']
        # iptables: Set default policy to DROP for INPUT chain
        cls.container.exec_run(f"iptables -A INPUT -p tcp --dport {cls.test_app_port} -j DROP")
        # nftables: Set default policy to drop
        cls.container.exec_run(f"nft add rule ip input_test in-knock-port tcp dport {cls.test_app_port} drop")
        
        print("nftables table and chain created, default drop rule added")
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
        
        # Test accessibility after knock
        response = requests.get(f'http://localhost:{self.test_app_port}')
        self.assertEqual(response.status_code, 200, "Port should be accessible after knock")

    def test_default_drop(self):
        # Test that the port is not accessible by default
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get(f'http://localhost:{self.test_app_port}', timeout=1)

    def test_port_accessibility(self):
        # Knock to open the port
        response = requests.post('http://localhost:8080', data={'app': 'test_app', 'access_key': 'test_secret'})
        self.assertEqual(response.status_code, 503)

        # Wait for the rule to be applied
        time.sleep(2)

        # Test accessibility
        response = requests.get(f'http://localhost:{self.test_app_port}')
        self.assertEqual(response.status_code, 200, "Port should be accessible after knock")

        # Wait for the rule to expire
        with open('config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        sleep_duration = config['test_app']['duration'] + 5
        time.sleep(sleep_duration)

        # Test that the port is no longer accessible
        with self.assertRaises(requests.exceptions.ConnectionError):
            requests.get(f'http://localhost:{self.test_app_port}', timeout=1)

    def test_session_expiration(self):
        # Load the config file
        with open('config.test.yaml', 'r') as config_file:
            config = yaml.safe_load(config_file)
        
        # Get the duration from the config and add 5 seconds
        sleep_duration = config['test_app']['duration'] + 5
        
        response = requests.post('http://localhost:8080', data={'app': 'test_app', 'access_key': 'test_secret'})
        self.assertEqual(response.status_code, 503)
        
        time.sleep(sleep_duration)

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
