# KnockPort

> Check a comprehensive wiki at https://deepwiki.com/torson/knock-port

A port-knocking server with a HTTP+HTTPS request procedure to open service port(s) - either running locally or on an internal LAN host (forwarding the traffic).

You can continue having that old application/service you love to use faced to public internet even though it might have security holes (most probably it's littered with them). Or use it for any latest service you're using since it most probably also has security holes. With KnockPort you open such application/service port only for the IP you're doing the request procedure from.

Of course if there's a rouge actor on your network (public WiFi ;) ), then KnockPort is of no benefit in protecting your service(s) since the actor has the same access as you - the same public IP.

KnockPort needs permission to modify kernel-level firewall settings. It can be run as root user, or as a regular user with sudo permissions using the `--use-sudo` flag.

It supports iptables, nftables and VyOS specific nftables.

## Configuration
It uses a configuration file to define app names, their corresponding ports, access keys, duration for which the port should remain open and so on. Example:
```yaml
global:
  http_post_path: /1-SECRET   # limited to 10 characters unfortunately due to nftables firewall limits , set custom value, don't leave it default
  https_post_path: /2-SECRET  # set custom value (not length limited), don't leave it default
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
# > 2 files get created: tests/knockport.testing.key , tests/knockport.testing.pem
GENERATE_CERTIFICATE_ONLY=true tests/run_docker_tests.sh

# using nftables, root user
sudo python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knockport.testing.pem --key tests/knockport.testing.key

# using nftables, non-root user (recommended)
python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo

# Sample curl commands to authenticate and test the server with the sample configuration
# > they should be run one after the other (depending what step2_https_duration is set to)
curl -d 'app=app1&access_key=secret123_http' -m 1 http://knockport.example.com/{SECRET_1}
curl -d 'app=app1&access_key=secret456_https' -k https://knockport.example.com/{SECRET_2}

# at this point the service port should be open for your IP
```

## Running as Non-Root User (Recommended)

For better security, KnockPort can run as a regular user with sudo permissions for firewall management:

### 1. Create a dedicated user (optional but recommended):
```bash
sudo adduser knockport
```

### 2. Set up sudo permissions:
```bash
# Copy the provided sudoers template
sudo cp var/knockport-sudoers.dist /etc/sudoers.d/knockport

# If you're using a different username, edit the file:
sudo nano /etc/sudoers.d/knockport

# Set proper permissions
sudo chmod 440 /etc/sudoers.d/knockport

# Verify configuration
sudo visudo -c
```

Manual sudoers setup (alternative):
```bash
# For iptables
echo "knockport ALL=NOPASSWD: /usr/sbin/iptables *" | sudo tee /etc/sudoers.d/knockport

# For nftables
echo "knockport ALL=NOPASSWD: /usr/sbin/nft *" | sudo tee -a /etc/sudoers.d/knockport
```

### 3. Run KnockPort with --use-sudo:
```bash
# Switch to the knockport user
sudo su - knockport

# Run KnockPort (example with nftables)
python src/main.py -c config/config.yaml --firewall-type nftables --http-port 8080 --https-port 4431 --cert tests/knockport.testing.pem --key tests/knockport.testing.key --use-sudo
```

## Using with systemd:
```
cp var/knockport.service.dist var/knockport.service
# Update the app arguments inside knockport.service
# For non-root user: add --use-sudo flag and set User=knockport
# For root user: remove --use-sudo flag and set User=root
cp var/knockport.service /etc/systemd/system/knockport.service
systemctl daemon-reload
systemctl enable knockport.service
systemctl start knockport.service
systemctl status knockport.service
journalctl -u knockport.service
journalctl -fu knockport.service

## on VyOs there needs to be a delay on boot
# service needs to be disabled because we're using a timer (knockport.timer)
# to do a delayed start on boot, otherwise nftables are not yet properly loaded
# which causes backend traffic not to get through even though KnockPort
# created all needed nftables rules
systemctl disable knockport.service
cp var/knockport.timer /etc/systemd/system/knockport.timer
systemctl daemon-reload
systemctl enable knockport.timer
```

## How it works

To open a configured service port you need to make 2 requests, first HTTP and then HTTPS.
It checks if the request payload matches an app name and access key in the configuration file. If there's a match, it opens the HTTPS port for client IP for a limited duration as specified in the configuration. After a valid HTTPS request it opens up the service port for client IP. The server manages open port "sessions" and automatically closes the port for the client IP after the duration expires.

There are 3 ports involved in the basic setup :
1. HTTP port: for step-1, stealthy - On the firewall level it responds only with the TCP initialization phase packets (SYN and ACK). Only single-TCP-packet requests are allowed and only those that are `POST /_CONFIGURED_PATH_` requests, which blocks all blind brute-force and random rouge requests on the firewall level so they don't even get to the webserver. The HTTP response is blocked, so the HTTP client doesn't get the actual response - it just waits till timeout . A valid request (POST request with a valid secret key for step-1) opens up HTTPS port for that client IP. One needs to know the exact `/_CONFIGURED_PATH_` to get through. This can be obtained on the network if the attacker does packet sniffing on the same network where a valid HTTP request happens
2. HTTPS port: for step-2, closed by default, opened only for a time window (configured with `step2_https_duration`) for the client IP after a valid HTTP request. A valid request (POST request with a valid secret key for step-2) opens up service port for that client IP. As the request is HTTPS, packet sniffing by an attacker will not reveal either request path or the secret key for step-2.
3. service port: closed by default , opened only for a time window (configured with `duration`) for the client IP after a valid HTTPS request was made.

2-step approach is needed, because HTTPS port can't be made stealthy due to the nature of HTTPS handshake, and HTTP is plaintext so a network sniffer can easily catch the access key - that's why the step-1 and step-2 access keys should be different. Also there can be multiple keys defined, so each user can have different/unique pairs.
So step-1 is to hide the setup from public, and step-2 is to secure the setup (to some degree. If you enable 2FA then HTTPS is secured) from step-1 network sniffing. In such a case the attacker can still attack the HTTPS port.

#### Notes:
- KnockPort uses Flask web-server which is not meant for production use (security is not its 1st priority). There is a FlaskForm form checker and flask_limiter rate limiter in place to remedy attacks. Since how KnockPort sets up firewall for stealthy HTTP and limiting HTTP request to 500B it's highly probable there's no way to hack the HTTP port. If 2FA is not used then an attacker can repeat the HTTP request which opens up the HTTPs port for defined number of seconds and that is a window for attacking the Flask HTTPS port. A more security-aware web server like Nginx should be put in front to improve security of KnockPort even more. If the web server is run on the same host as KnockPort, then use arguments --waf-http-port and --waf-https-port to set those ports so firewall rules are set up correctly.
- nftables were introduced in kernel 3.13 and Linux distributions started using it by default a few years later (from RHEL8/Debian10/Ubuntu20.04 onwards). This means iptables commands get translated to nftables, which means that various iptables modules are not supported if there's no equivalent nftables support. So use `--firewall-type iptables` only on systems that still use iptables by default (older than RHEL8/Debian10/Ubuntu20.04) .


### Detailed Breakdown of the stealthy HTTP request/response procedure
1. Client (curl) sends POST request:

- TCP SYN to establish connection.
- TCP SYN-ACK from server (allowed by iptables/nftables rule).
- TCP ACK from client to complete the handshake.
- HTTP POST request sent over the established TCP connection (this can also be part of TCP ACK packet).

2. Server receives POST request:

- Due to iptables/nftables rules, the server host does not send an ACK back for the HTTP POST data (web server sends it, but it's dropped by the firewall).
- The TCP stack on the client side waits for an ACK or response. As the ACK never comes there's TCP stack retransmission:
- After a timeout, the client's TCP stack retransmits the HTTP POST request.
- This continues, following the exponential backoff strategy, until it reaches the maximum retransmission limit.

Note: After the addition of firewall level filtering of HTTP URL path (which was not in the initial design), this response blocking is actually not really needed anymore, but I still left it in.

## 2FA

You can enable 2FA to prevent abuse in case your machine gets compromised. Might be better to use an authenticator app on your phone instead of one on the machine itself (like 1Password that also supports 2FA tokens).

To set up 2FA run this command and pass it any access_key_http value that's configured in `config.yaml` for which you want to enable 2FA, and follow instructions:
```
python src/setup_2fa.py -h
python src/setup_2fa.py -k {access_key_http}
```

Two files were created inside folder `config/2fa/` : `<access_key>_qr.png` and `<access_key>.json` .

From this point onward you need to provide additional header `token` in the curl command when authenticating with this specific access_key :
```
#!/bin/bash
read -p "2FA token: " TOKEN
curl -d "app=app1&access_key=secret123_http&token=${TOKEN}" -m 1 http://knockport.example.com/1-{SECRET}
curl -d "app=app1&access_key=secret456_https" -k https://knockport.example.com/2-{SECRET}
```

A valid token can be used only once to prevent an attacker sniffing the network to repeat the same request from another IP, so in case you fail to send the 2nd step HTTPS request within the configured `step2_https_duration` value (if it's set to a low value), then you need to wait for the next 2FA token to be generated and pass that new token.

To disable 2FA for a particular access_key , just rename/move/delete file `config/2fa/<access_key>.json` .

In addition of securing the services ports, enabling 2FA also shields KnockPort from attacks on HTTPS port because the token is passed with the 1st step HTTP request (there's nothing wrong with sending tokens via HTTP as the 2FA key can't get reverse-engineered with sampling of tokens), so the 2nd step HTTPS port doesn't even get open for attacks.


## TODO
- option to define cli commands in config.yaml to run for opening and closing a service port per app, so KnockPort can manage cloud firewall like AWS Security Group. Management requests could come in via ALB (--waf-* arguments) and KnockPort would then manage one AWS SecurityGroup per app
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

