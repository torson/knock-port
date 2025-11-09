# KnockPort

A port-knocking firewall manager. A modern take on traditional port knocking with 2FA support. KnockPort opens service ports for an IP via a authenticated two-step HTTP → HTTPS flow, then closes them automatically after a configured period. Use it to safely expose legacy or internal services without leaving ports publicly reachable.

- Two-step port open: path-filtered HTTP + HTTPS authentication
- Per-IP access with time-limited windows
- Local services or LAN hosts (port forwarding)
- Works with iptables, nftables, and VyOS nftables
- Run it as root or as non-root with `--use-sudo`
- Optional 2FA for added protection
- systemd templates and Docker-based tests included

## Configuration
It uses a configuration file to define app names, their corresponding ports, access keys, duration for which the port should remain open and so on. Example:
```yaml
global:
  http_post_path: /SECRET-1   # limited to 10 characters unfortunately due to nftables firewall limits , set custom value, don't leave it default
  https_post_path: /SECRET-2  # set custom value (not length limited), don't leave it default
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
# > they should be run one after the other within the step2_https_duration window (set in config.yaml)
curl -d 'app=app1&access_key=secret123_http' -m 1 http://knockport.example.com/{SECRET_1}
curl -d 'app=app1&access_key=secret456_https' -m 1 -k https://knockport.example.com/{SECRET_2}

# at this point the service port should be open for your IP
```


## How It Works
- Step 1 (HTTP): client posts a request to initiate step 2. Firewall rules keep the HTTP endpoint path-filtered so invalid-path requests are dropped at the firewall before they reach KnockPort, while valid requests complete the TCP flow and receive an HTTP response.
- Step 2 (HTTPS): upon a valid step 1, HTTPS opens briefly for the requester IP to submit the second secret. On success, the target service port opens for a configured duration for that IP.

## Security Notes
- 2FA is supported and recommended for compromised-client computer scenarios.
- Consider placing a hardened reverse proxy / WAF (Nginx for example) in front if desired (set `--waf-http-port`, `--waf-https-port`).
- HTTPS cannot be fully stealth due to TLS handshakes; keep the step 2 open window short.
- Use `--firewall-type iptables` on systems that still default to iptables; modern distros translate iptables to nftables.

## Operating Tips
- Non-root: run with `--use-sudo` and configure `/etc/sudoers.d/` (see `var/knockport-sudoers.dist`).
- systemd: use `var/knockport.service.dist` (and `knockport.timer` on VyOS to delay startup until nftables is ready).
- Tests: run `tests/run_docker_tests.sh`. For VyOS, set `VYOS_ROLLING_VERSION` in `tests/.env`.

## License
See `LICENSE`.

## Extra

For extended readme check README.extended.md .
