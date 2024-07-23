
# Knock-Port

This app implements a port-knock approach using a 2-step HTTP and HTTPS POST request procedure to open a service port - either running locally or on an internal LAN host (forwarding the traffic).

It checks if the POST request payload matches an app name and access key in the configuration file. If there's a match, it opens the port for the client IP for a limited duration as specified in the configuration. The server manages sessions and automatically closes the service port for the client IP after the duration expires.

There are 3 ports in the procedure :
1. HTTP port: for step-1, stealthy - On the firewall level it responds only with the TCP initialization step packets (SYN and ACK). Only single-TCP-packet requests are allowed and only those that are `POST /_CONFIGURED_PATH_` requests, which blocks all brute-force and random rouge requests so they don't even come to the webserver. The HTTP response is blocked, so the HTTP client doesn't get the actual response - it just waits till timeout . A valid request (POST request with a valid secret key for step-1) opens up HTTPS port for that client IP. One needs to know the exact `/_CONFIGURED_PATH_` to get through. This can be obtained on the network if the attacker does packet sniffing on the same network where a valid client resides while doing a valid HTTP request
2. HTTPS port: for step-2, closed by default, opened only for a time window (configured with `step2_https_duration`) after a valid HTTP request for the client IP . A valid request (POST request with a valid secret key for step-2) opens up service port for that client IP. As the request is HTTPS, packet sniffing by an attacker will not reveal either POST request path or the secret key for step-2
3. service port: closed by default , opened only for a time window (configured with `duration`) after a valid HTTPS request for the client IP


2-step approach is needed, because HTTPS port can't be made stealthy due to the nature of HTTPS handshake, and HTTP is plaintext so a network sniffer can easily catch the access key - that's why the step-1 and step-2 access keys should be different. Also each user can have different/unique pairs.

So step-1 is to hide the setup from public, and step-2 is to secure the setup from step-1 network sniffing.

### Detailed Breakdown of the 2-step procedure
Client (curl) sends POST request:

TCP SYN to establish connection.
TCP SYN-ACK from server (allowed by nftables rule).
TCP ACK from client to complete the handshake.
HTTP POST request sent over the established TCP connection (this can also be part of TCP ACK packet).
Server receives POST request:

Due to nftables rules, the server does not send an ACK back for the HTTP POST data.
The TCP stack on the client waits for an ACK or response. As the ACK never comes there's TCP stack retransmission:
After a timeout, the client’s TCP stack retransmits the HTTP POST request.
This continues, following the exponential backoff strategy, until it reaches the maximum retransmission limit.


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
curl -m 1 -d 'app=app1&access_key=secret123' http://knock-port.example.com/step-1
curl -m 1 -d 'app=app1&access_key=secret456' -k https://knock-port.example.com/step-2
```


## Testing
There's a Unittest suite of tests for using iptables, nftables and VyOs specific nftables tables and chains. Run it with:
```
tests/run_docker_tests.sh
```
