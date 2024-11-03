
# Knock-Port

A port-knocking server with a HTTP+HTTPS request procedure to open service port(s) - either running locally or on an internal LAN host (forwarding the traffic).

You can continue having that old application/service you love to use faced to public internet even though it might have security holes (most probably it's littered with them). Or use it for any latest service you're using since it most probably also has security holes. With Knock-Port you open such application/service port only for the IP you're doing the request procedure from.

Of course if there's a rouge actor on your network (public WiFi ;) ), then Knock-Port is of no benefit in protecting your service(s) since the actor has the same access as you - the same public IP.

Knock-Port needs permission to modify kernel-level firewall settings, so it must either be:
- run as root user or with sudo
- run as regular user and with argument '--run-with-sudo'. The iptables/nft command needs to be added into a sudoers file for that user. In this case both HTTP/HTTPS ports need to be higher than 1024 (for lower ports root permission on the whole app is required)

## Configuration
It uses a configuration file to define app names, their corresponding ports, access keys, duration for which the port should remain open and so on. Example:
```yaml
global:
  http_post_path: /step-1-SECRET
  https_post_path: /step-2-SECRET
  step1_2_rate_limit_per_minute: 5
  interface_ext: eth0
  interface_int: eth0  # used in case of non-local service and router using 2 separate interfaces

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
sudo python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key

# Sample curl command sto test the server with the sample configuration
# 2 curl commands are required, first http then https
# (You need to change default value `/step-1-SECRET` and `/step-2-SECRET`, otherwise it'll error out) :
curl -m 1 -d 'app=app1&access_key=secret123_http' http://knock-port.example.com/step-1-{SECRET}
curl -m 1 -d 'app=app1&access_key=secret456_https' -k https://knock-port.example.com/step-2-{SECRET}

# at this point the service port should be opened for your IP
```

Using with sudoers config:
```
# if using iptables
echo "knockport ALL=NOPASSWD: /usr/sbin/iptables *" > /etc/sudoers.d/knockport
# if using nftables
echo "knockport ALL=NOPASSWD: /usr/sbin/nft *" > /etc/sudoers.d/knockport

# don't run the app with sudo but add argument '--run-with-sudo'
# this will then run all firewall commands with sudo
python src/main.py -c config/config.yaml --firewall-type nftables --http-port 8080 --https-port 4431 --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key --run-with-sudo
```

Using with nohup:
```
nohup sudo python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key >> knock-port-server.log &
```


Managing with systemd service:
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

## How it works

To open a configured service port you need to make 2 requests, first HTTP and then HTTPS.
It checks if the request payload matches an app name and access key in the configuration file. If there's a match, it opens the HTTPS port for client IP for a limited duration as specified in the configuration. After a valid HTTPS request it opens up the service port for client IP. The server manages open port "sessions" and automatically closes the port for the client IP after the duration expires.

There are 3 ports involved:
1. HTTP port: for step-1, stealthy - On the firewall level it responds only with the TCP initialization phase packets (SYN and ACK). Only single-TCP-packet requests are allowed and only those that are `POST /_CONFIGURED_PATH_` requests, which blocks all blind brute-force and random rouge requests on the firewall level so they don't even get to the webserver. The HTTP response is blocked, so the HTTP client doesn't get the actual response - it just waits till timeout . A valid request (POST request with a valid secret key for step-1) opens up HTTPS port for that client IP. The whole request can be obtained on the network if the attacker does packet sniffing on the same network where a valid HTTP request happens
2. HTTPS port: for step-2, closed by default, opened only for a time window (configured with `step2_https_duration`) for the client IP after a valid HTTP request. A valid request (POST request with a valid secret key for step-2) opens up service port for that client IP. As the request is HTTPS, packet sniffing by an attacker will not reveal either request path or the secret key for step-2.
3. service port: closed by default , opened only for a time window (configured with `duration`) for the client IP after a valid HTTPS request was made.

2-step approach is needed because a HTTPS request can't be filtered on the firewall level and HTTP is plaintext so a network sniffer can easily catch the access key - that's why the step-1 and step-2 access keys should be different. Also there can be multiple keys defined, so each user can have different/unique pairs.
So step-1 is to hide the setup from public, and step-2 is to secure the setup from step-1 network sniffing. If 2FA is not used, the attacker can still attack the HTTPS port via some Flask vulnerability.

Supports iptables, nftables and VyOS specific nftables (it was written for protecting OpenVPN port on VyOS).

Notes:
- nftables were introduced in kernel 3.13 and Linux distributions started using it by default a few years later (from RHEL8/Debian10/Ubuntu20.04 onwards). This means iptables commands get translated to nftables, which means that some iptables modules are not supported if there's no equivalent nftables support. So use `--firewall-type iptables` only on systems that still use iptables by default (older than RHEL8/Debian10/Ubuntu20.04) .
- Knock-Port uses Flask web-server which is not meant for production use (security is not its 1st priority). There is a FlaskForm form checker and flask_limiter rate limiter in place to remedy attacks. Since how Knock-Port sets up firewall for filtering HTTP and making the port stealthy, it's highly probable there's no way to hack the Flask HTTP port. If 2FA is not used then an attacker can repeat the HTTP request which opens up the HTTPs port for defined number of seconds and that is a window for attacking the Flask HTTPS port. A more security-aware web server like Nginx can be put in front to improve security of Knock-Port. If the web server is run on the same host as Knock-Port, then add arguments `--waf-http-port` and `--waf-https-port` to set those ports so firewall rules are set up correctly.


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

After the addition of firewall level filtering of HTTP URL path (which was not in the initial design), this response blocking is not really needed anymore for making Knock-Port stealthy, but it's still present as a potential security measure against attacks.


## 2FA

You can enable 2FA to prevent abuse in case your machine gets compromised. Use Authenticator on your phone instead of one on the machine itself - like 1Password which also supports 2FA tokens.

To set up 2FA run this command and pass it any access_key_http (configured in config.yaml) value for which you want to enable 2FA, and follow instructions:
```
python src/setup_2fa.py -h
python src/setup_2fa.py -k {access_key_http}
```

From this point onwards you need to provide additional header `token` in the curl command :
```
curl -m 1 -d 'app=app1&access_key=secret123_http&token=123456' http://knock-port.example.com/step-1-{SECRET}

```

A valid token can be used only once to prevent an attacker (sniffing the network) repeating the same request from another IP, so in case you fail to send the HTTPS request within the configured `step2_https_duration` value (if it's set to a low value), then you need to wait for the next token to generate.

In addition of securing the services ports, enabling 2FA also shields Knock-Port itself from attacks on HTTPS port because the token is passed with the 1st step HTTP request (there's nothing wrong with sending tokens via HTTP as the 2FA key can't get reverse-engineered with sampling of tokens), so the 2nd step HTTPS port doesn't even get open for attacks.


## TODO
- OTP token (separate from 2FA) added to HTTP request so network sniffing becomes unuseful, the attacker needs to break into the client computer. The token needs to be generated on the client side so it must have the token generation set up in addition to just using curl


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

