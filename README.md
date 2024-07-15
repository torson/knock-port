
# Server Application

## Description
This server application implements a port-knock approach using 2-phase HTTP and HTTPS POST requests to open a service port - either running locally or on an internal LAN host (forwarding the traffic).

It checks if the POST request payload matches an app and access key in the configuration file. If there's a match, it opens the port for the client IP for a limited duration as specified in the configuration. The server manages sessions and automatically closes the service port for the client IP after the duration expires.

There are 3 ports in the procedure :
1. HTTP port: for phase-1, stealthy - responds only with the TCP initialization phase packets (SYN and ACK) , only so that the server can handle a single TCP packet HTTP request. The HTTP response is blocked, so the HTTP client doesn't get the actual response - it just waits till timeout . A valid request (POST request with a valid secret key for phase-1) opens up HTTPS port for that client IP
2. HTTPS port: for phase-2, closed by default, opened only for a time window  after a valid HTTP request for the client IP . A valid request (POST request with a valid secret key for phase-2) opens up service port for that client IP
3. service port: closed by default , opened only for a time window (configured with `duration`) after a valid HTTPS request for the client IP


2-phase approach is needed, because HTTPS port can't be made stealthy due to the nature of HTTPS handshake, and HTTP is plaintext so a network sniffer can easily catch the access key - that's why the phase-1 and phase-2 access keys should be different. Also each user can have different/unique pairs.

So phase-1 is to hide the setup from public, and phase-2 is to secure the setup from phase-1 network sniffing.

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
```
python3 src/server.py -h

nohup /root/venv/bin/python src/server.py -c src/config.yaml --routing-type vyos --nftables-chain-input NAME_IN-OpenVPN-KnockPort --http-port 80 --https-port 443 --cert /config/auth/easy-rsa/pki/issued/server.crt --key /config/auth/easy-rsa/pki/private/server.key >> knock-port-server.log &

# Sample curl command to test the server with the sample configuration:
curl -m 1 -d 'app=app1&access_key=secret123' http://knock-port.example.com/phase-1
curl -m 1 -d 'app=app1&access_key=secret456' -k https://knock-port.example.com/phase-2
```


## Testing
There's a Unittest suite of tests for using iptables, nftables and VyOs specific nftables tables and chains. Run it with:
```
tests/run_docker_tests.sh
```
