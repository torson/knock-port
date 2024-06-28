
import requests
import time
import unittest
import docker
import json

class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = docker.from_env()
        cls.container = cls.client.containers.get('port-knock-server')
        
        # Create nftables table and chain
        cls.container.exec_run('nft add table ip vyos_filter')
        cls.container.exec_run('nft add chain ip vyos_filter NAME_IN-OpenVPN-KnockPort { type filter hook input priority filter; policy accept; }')
        
        print("nftables table and chain created")
        print("Container logs:")
        print(cls.container.logs().decode('utf-8'))
    @classmethod
    def setUpClass(cls):
        cls.client = docker.from_env()
        cls.container = cls.client.containers.get('port-knock-server')

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def test_session_creation(self):
        response = requests.post('http://localhost:8080', data={'app': 'openvpn', 'access_key': 'secret123'})
        self.assertEqual(response.status_code, 503)
        
        # Check the session_cache.json file inside the container
        exec_result = self.container.exec_run('cat /app/session_cache.json')
        sessions = exec_result.output.decode('utf-8')
        self.assertIn('"command":', sessions, "Session should be created")

    def test_session_expiration(self):
        response = requests.post('http://localhost:8080', data={'app': 'openvpn', 'access_key': 'secret123'})
        self.assertEqual(response.status_code, 503)
        
        time.sleep(15)

        exec_result = self.container.exec_run('cat /app/session_cache.json')
        sessions = exec_result.output.decode('utf-8')
        self.assertEqual(sessions.strip(), '[]', "Session should be expired and removed from the cache")

    def test_invalid_access_key(self):
        response = requests.post('http://localhost:8080', data={'app': 'openvpn', 'access_key': 'invalidkey'})
        self.assertEqual(response.status_code, 503)

    def test_invalid_app_name(self):
        response = requests.post('http://localhost:8080', data={'app': 'invalidapp', 'access_key': 'secret123'})
        self.assertEqual(response.status_code, 503)

    def test_missing_data(self):
        response = requests.post('http://localhost:8080', data={})
        self.assertEqual(response.status_code, 503)

    def test_get_request(self):
        response = requests.get('http://localhost:8080')
        self.assertEqual(response.status_code, 404)

if __name__ == "__main__":
    unittest.main()
