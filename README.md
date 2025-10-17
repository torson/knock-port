# Knock-Port

A lightweight, on-demand port-knocking gateway. Knock-Port opens service ports only for the IP that proves knowledge of a shared secret via a two-step HTTP → HTTPS flow, then closes them automatically after a configured period. Use it to safely expose legacy or internal services without leaving ports publicly reachable.

- Two-step open: stealth HTTP + HTTPS authentication
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
# > 2 files get created: tests/knock-port.testing.key , tests/knock-port.testing.pem
GENERATE_CERTIFICATE_ONLY=true tests/run_docker_tests.sh

# using nftables, root user
sudo python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key

# using nftables, non-root user (recommended)
python src/main.py -c config/config.yaml --firewall-type nftables --http-port 80 --https-port 443 --cert tests/knock-port.testing.pem --key tests/knock-port.testing.key --use-sudo

# Sample curl commands to authenticate and test the server with the sample configuration
# > they should be run one after the other (depending what step2_https_duration is set to)
curl -d 'app=app1&access_key=secret123_http' -m 1 http://knock-port.example.com/{SECRET_1}
curl -d 'app=app1&access_key=secret456_https' -k https://knock-port.example.com/{SECRET_2}

# at this point the service port should be open for your IP
```


## How It Works
- Step 1 (HTTP): client posts to a secret path. Firewall rules keep the HTTP endpoint stealthy (client doesn't receive the response) and path-filtered .
- Step 2 (HTTPS): upon a valid step 1, HTTPS opens briefly for the requester IP to submit the second secret. On success, the target service port opens for a configured duration for that IP.

## Security Notes
- HTTPS cannot be fully stealth due to TLS handshakes; keep the step-2 open window short.
- Consider placing a hardened reverse proxy / WAF (Nginx for example) in front if desired (set `--waf-http-port`, `--waf-https-port`).
- 2FA is supported and recommended for compromised-client computer scenarios.
- Use `--firewall-type iptables` on systems that still default to iptables; modern distros translate iptables to nftables.

## Operating Tips
- Non-root: run with `--use-sudo` and configure `/etc/sudoers.d/` (see `var/knockport-sudoers.dist`).
- systemd: use `var/knock-port.service.dist` (and `knock-port.timer` on VyOS to delay startup until nftables is ready).
- Tests: run `tests/run_docker_tests.sh`. For VyOS, set `VYOS_ROLLING_VERSION` in `tests/.env`.

## License
See `LICENSE`.

## Extra

For extended readme check README.extended.md .
