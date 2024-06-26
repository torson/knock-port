
# Server Application

## Description
This server application listens for HTTP POST requests on port 8080. It checks if the POST request payload matches an app and access key in the configuration file. If there's a match, it opena a specified port for the app for a limited duration as specified in the configuration. The server manages sessions and automatically closes ports after the duration expires.

## Configuration
The server uses a YAML configuration file to define app names, their corresponding ports, access keys, and the duration for which the port should remain open. Here's an example of the configuration format:
```yaml
openvpn:
  port: 1194
  # destination: Can be "local" or "IP:PORT" - "local" uses the local server, "IP:PORT" forwards requests to the specified IP address and port
  destination: local
  duration: 300  # Duration in seconds
```

## Installation
1. Install the required packages:
```
pip install -r requirements.txt
```

## Usage
To run the server:
```
python3 server.py -c config.yaml
- `-c config.yaml` specifies the path to the configuration file. If omitted, `config.yaml` in the current directory is used by default.
- `-t` enables test mode, where `iptables` commands are mocked.

# Sample curl command to test the server with the sample configuration:
curl -X POST -d 'app=openvpn&access_key=secret123' http://localhost:8080
```

## Help
To display help information about the command-line arguments:
```
python3 server.py -h
```

## Testing
To test the server, especially the session expiration feature:
```
python3 test_server.py
```
Note: The session expiration test includes a sleep period that corresponds to the duration specified in the configuration. Adjust the duration for quicker tests.
