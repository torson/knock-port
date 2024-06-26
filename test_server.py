
import requests
import time
import json

def test_session_expiration():
    # Send a request to open a port
    response = requests.post('http://127.0.0.1:8080', data='openvpn=secret123')
    assert response.status_code == 503, "Expected status code 503"
    
    # Wait for the duration to expire
    time.sleep(310)  # Assuming the duration is 300 seconds, wait a bit longer

    # Check if the session has been removed
    with open('session_cache.json', 'r') as f:
        sessions = json.load(f)
    assert len(sessions) == 0, "Session should be expired and removed from the cache"
    print("Test for session expiration passed.")

if __name__ == "__main__":
    test_session_expiration()
