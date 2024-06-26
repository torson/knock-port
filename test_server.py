
import requests
import time
import json

def test_session_expiration():
    # Send a request to open a port
    response = requests.post('http://127.0.0.1:8080', data={'app': 'openvpn', 'access_key': 'secret123'})
    assert response.status_code == 503, "Expected status code 503"
    
    # Wait for the duration to expire
    time.sleep(310)  # Assuming the duration is 300 seconds, wait a bit longer

    # Check if the session has been removed
    with open('session_cache.json', 'r') as f:
        sessions = json.load(f)
    assert len(sessions) == 0, "Session should be expired and removed from the cache"
    print("Test for session expiration passed.")

def test_invalid_access_key():
    # Send a request with an invalid access key
    response = requests.post('http://127.0.0.1:8080', data={'app': 'openvpn', 'access_key': 'invalidkey'})
    assert response.status_code == 503, "Expected status code 503 for invalid access key"
    print("Test for invalid access key passed.")

def test_invalid_app_name():
    # Send a request with an invalid app name
    response = requests.post('http://127.0.0.1:8080', data={'app': 'invalidapp', 'access_key': 'secret123'})
    assert response.status_code == 503, "Expected status code 503 for invalid app name"
    print("Test for invalid app name passed.")

def test_missing_data():
    # Send a request with missing data
    response = requests.post('http://127.0.0.1:8080', data={})
    assert response.status_code == 400, "Expected status code 400 for missing data"
    print("Test for missing data passed.")

if __name__ == "__main__":
    test_session_expiration()
    test_invalid_access_key()
    test_invalid_app_name()
    test_missing_data()
