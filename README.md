
# Knock-Port

A port-knocking server with a 2-step HTTP and HTTPS POST request procedure to open a service port - either running locally or on an internal LAN host (forwarding the traffic).

It checks if the POST request payload matches an app name and access key in the configuration file. If there's a match, it opens the port for the client IP for a limited duration as specified in the configuration. The server manages open port "sessions" and automatically closes the service port for the client IP after the duration expires.

It supports iptables, nftables and VyOS specific nftables (it was written to be used on VyOS).

Note:
Nftables were introduced in kernel 3.13 and Linux distributions started using it by default a few years later (from RHEL8/Debian10/Ubuntu20.04 onwards). This means iptables commands get translated to nftables, which means that various iptables modules are not supported if there's no equivalent nftables support. So use `--firewall-type iptables` only on systems that still use iptables by default (older than RHEL8/Debian10/Ubuntu20.04) .

## Configuration
The server uses a YAML configuration file to define app names, their corresponding ports, access keys, duration for which the port should remain open, ... Example:
```yaml
global:
  http_post_path: /step-1-SECRET
  https_post_path: /step-2-SECRET
  step1_2_rate_limit_per_minute: 5
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
  destination: local
  protocol: udp
  duration: 86400          # 24h ; Duration in seconds
  step2_https_duration: 5  # seconds
```

## Usage
```
pip install -r requirements.txt
python src/main.py -h

# for generating self-signed certificate run this
GENERATE_CERTIFICATE_ONLY=true tests/run_docker_tests.sh

# using nftables
python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key

# Sample curl command to test the server with the sample configuration:
curl -m 1 -d 'app=app1&access_key=secret123_http' http://knock-port.example.com/step-1-SECRET
curl -m 1 -d 'app=app1&access_key=secret456_https' -k https://knock-port.example.com/step-2-SECRET

# at this point the service port should be opened
```

Using with nohup:
```
nohup python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key >> knock-port-server.log &
```


Using as systemd service:
```
cp var/knock-port.service.dist cp var/knock-port.service
# > update the app arguments
cp var/knock-port.service /etc/systemd/system/knock-port.service
systemctl daemon-reload
systemctl enable knock-port.service
systemctl start knock-port.service
systemctl status knock-port.service
journalctl -u knock-port.service
journalctl -fu knock-port.service
```

## Description

There are 3 ports involved in the basic setup :
1. HTTP port: for step-1, stealthy - On the firewall level it responds only with the TCP initialization phase packets (SYN and ACK). Only single-TCP-packet requests are allowed and only those that are `POST /_CONFIGURED_PATH_` requests, which blocks all blind brute-force and random rouge requests so they don't even get to the webserver. The HTTP response is blocked, so the HTTP client doesn't get the actual response - it just waits till timeout . A valid request (POST request with a valid secret key for step-1) opens up HTTPS port for that client IP. One needs to know the exact `/_CONFIGURED_PATH_` to get through. This can be obtained on the network if the attacker does packet sniffing on the same network where a valid client resides while doing a valid HTTP request
2. HTTPS port: for step-2, closed by default, opened only for a time window (configured with `step2_https_duration`) for the client IP after a valid HTTP request. A valid request (POST request with a valid secret key for step-2) opens up service port for that client IP. As the request is HTTPS, packet sniffing by an attacker will not reveal either POST request path or the secret key for step-2.
3. service port: closed by default , opened only for a time window (configured with `duration`) for the client IP after a valid HTTPS request was made.


2-step approach is needed, because HTTPS port can't be made stealthy due to the nature of HTTPS handshake, and HTTP is plaintext so a network sniffer can easily catch the access key - that's why the step-1 and step-2 access keys should be different. Also there can be multiple keys defined, so each user can have different/unique pairs.

So step-1 is to hide the setup from public, and step-2 is to secure the setup (to some degree) from step-1 network sniffing. In such a case the attacker can still attack the HTTPS port. There is a FlaskForm form checker and flask_limiter rate limiter in place to remedy the attack. A more security-aware web server like Nginx should be put in front the HTTPS port for such a case.

### Detailed Breakdown of the HTTP request/response procedure
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

Actually after the addition of firewall level filtering of HTTP URL path (which was not in the initial design), this response blocking is not really needed anymore, but I still left it there.

## TODO
- add test case for blocking request at the firewall level
- add arguments --waf-http-port and --waf-https-port in case you add Nginx/WAF in front of KnockPort as firewall rules need to be set up for the public-faced ports
- for vyos tests add also Nginx in front of HTTPS and setting client_max_body_size 100;
- OTP token added to access_key for HTTP request so network sniffing becomes unuseful, the attacker needs to break into the client computer
- 2FA token for HTTPS request in case IP is not yet in sessions - first HTTPS request gives specific 4XX status code, so a dialog is opened for the token that gets then passed on to HTTPS on 2nd request. This is for client computer breach case, so the attacker can't use the client setup from a remote machine. This secures the services ports. But HTTPS port is open for attack as HTTP OTP token has been breached at this point. Nginx/WAF should be put in front of HTTPS port to lower the chances of a successful attack on Flask

## Tests
There's a Unittest suite of tests for using iptables, nftables and VyOs specific nftables chains. Run it with:
```
tests/run_docker_tests.sh
```

For testing against VyOS you need to set var VYOS_ROLLING_VERSION with correct value in tests/.env , check https://github.com/vyos/vyos-nightly-build/releases :
```
export VYOS_ROLLING_VERSION=1.5-rolling-202410280007
```
The `run_docker_tests.sh` will download the ISO file and generate a docker image from it.

