
# Knock-Port

This app implements a port-knock approach using a 2-step HTTP and HTTPS POST request procedure to open a service port - either running locally or on an internal LAN host (forwarding the traffic).

It checks if the POST request payload matches an app name and access key in the configuration file. If there's a match, it opens the port for the client IP for a limited duration as specified in the configuration. The server manages sessions and automatically closes the service port for the client IP after the duration expires.

There are 3 ports in the procedure :
1. HTTP port: for step-1, stealthy - On the firewall level it responds only with the TCP initialization step packets (SYN and ACK). Only single-TCP-packet requests are allowed and only those that are `POST /_CONFIGURED_PATH_` requests, which blocks all brute-force and random rouge requests so they don't even come to the webserver. The HTTP response is blocked, so the HTTP client doesn't get the actual response - it just waits till timeout . A valid request (POST request with a valid secret key for step-1) opens up HTTPS port for that client IP. One needs to know the exact `/_CONFIGURED_PATH_` to get through. This can be obtained on the network if the attacker does packet sniffing on the same network where a valid client resides while doing a valid HTTP request
2. HTTPS port: for step-2, closed by default, opened only for a time window (configured with `step2_https_duration`) after a valid HTTP request for the client IP . A valid request (POST request with a valid secret key for step-2) opens up service port for that client IP. As the request is HTTPS, packet sniffing by an attacker will not reveal either POST request path or the secret key for step-2
3. service port: closed by default , opened only for a time window (configured with `duration`) after a valid HTTPS request for the client IP


2-step approach is needed, because HTTPS port can't be made stealthy due to the nature of HTTPS handshake, and HTTP is plaintext so a network sniffer can easily catch the access key - that's why the step-1 and step-2 access keys should be different. Also each user can have different/unique pairs.

So step-1 is to hide the setup from public, and step-2 is to secure the setup (to some degree) from step-1 network sniffing. In such a case the attacker can still attack the HTTPS port. There is a FlaskForm form checker and flask_limiter rate limiter in place to remedy the attack. A more security-aware web server like Nginx should be put in front the HTTPS port for such a case.

### Detailed Breakdown of the 2-step procedure
1. Client (curl) sends POST request:

- TCP SYN to establish connection.
- TCP SYN-ACK from server (allowed by iptables/nftables rule).
- TCP ACK from client to complete the handshake.
- HTTP POST request sent over the established TCP connection (this can also be part of TCP ACK packet).

2. Server receives POST request:

- Due to iptables/nftables rules, the server host does not send an ACK back for the HTTP POST data (web server sends it, but it's dropped by the firewall).
- The TCP stack on the client side waits for an ACK or response. As the ACK never comes there's TCP stack retransmission:
- After a timeout, the client’s TCP stack retransmits the HTTP POST request.
- This continues, following the exponential backoff strategy, until it reaches the maximum retransmission limit.


## Configuration
The server uses a YAML configuration file to define app names, their corresponding ports, access keys, and the duration for which the port should remain open. Here's an example of the configuration format:
```yaml
global:
  http_post_path: /step-1-SECRET
  https_post_path: /step-2-SECRET
  step1_2_rate_limit_per_minute: 120
  interface_ext: eth0
  interface_int: eth0  # used in case of non-local service

openvpn:
  port: 1194
  access_key_http:
    - test_secret_http
    - test_secret2_http
  access_key_https:
    - test_secret_https
    - test_secret2_https
  # destination: Can be "local" or "IP" or "IP:PORT" - "local" uses the local server, "IP:PORT" forwards requests to the specified IP address and port
  destination: local
  protocol: tcp
  duration: 86400   # 24h ; Duration in seconds
  step2_https_duration: 5
```

## TODO
- add arguments --waf-http-port and --waf-https-port in case you add Nginx/WAF in front of KnockPort as firewall rules need to be set up for the public-faced ports
- error out if http_post_path and https_post_path are default
- destination can have IP:PORT , currently only IP
- for vyos tests add also Nginx in front of HTTPS and setting client_max_body_size 100;
- OTP token added to access_key for HTTP request so network request sniffing becomes unuseful, the attacker needs to break into the client computer
- 2FA token for HTTPS request in case IP is not yet in sessions - first HTTPS request gives specific 4XX status code, so a dialog is opened for the token that gets then passed on to HTTPS on 2nd request. This is for client computer breach case, so the attacker can't use the client setup from a remote machine. This secures the services ports. But HTTPS port is open for attack as HTTP OTP token has been breached at this point. Nginx/WAF should be put in front of HTTPS port to lower the chances of a successful attack on Flask

## Installation
1. Install the required packages:
```
pip install -r requirements.txt
```

## Usage
```
python3 src/server.py -h

nohup /root/venv/bin/python src/server.py -c src/config.yaml --firewall-type iptables --http-port 80 --https-port 443 --cert server.crt --key server.key >> knock-port-server.log &

# Sample curl command to test the server with the sample configuration:
curl -m 1 -d 'app=app1&access_key=secret123_http' http://knock-port.example.com/step-1
curl -m 1 -d 'app=app1&access_key=secret456_https' -k https://knock-port.example.com/step-2
```


## Testing
There's a Unittest suite of tests for using iptables, nftables and VyOs specific nftables chains. Run it with:
```
tests/run_docker_tests.sh
```
