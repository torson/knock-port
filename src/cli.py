import argparse
from utils import log

def parse_args():
    parser = argparse.ArgumentParser(description="Server Application")
    parser.add_argument('-c', '--config', type=str, default='config/config.yaml', help='Path to the configuration file. By default `config/config.yaml` is used')
    parser.add_argument('--http-port', type=int, default=8080, help='Port to run the HTTP server on (default: 8080)')
    parser.add_argument('--https-port', type=int, default=8443, help='Port to run the HTTPS server on (default: 8443)')
    parser.add_argument('--cert', type=str, help='Path to the TLS certificate file. This can be server certificate alone, or a bundle of (1) server, (2) intermediary and (3) root CA certificate, in this order, like TLS expects it')
    parser.add_argument('--key', type=str, help='Path to the TLS key file')
    parser.add_argument('--firewall-type', type=str, default='nftables', choices=['iptables', 'nftables', 'vyos'], help='Type of routing to use (default: nftables , used from RHEL8/Debian10/Ubuntu20.04 onwards)')
    parser.add_argument('--nftables-table-filter', type=str, help='filter table to be used for filter chains (vyos: defaults to vyos_filter)')
    parser.add_argument('--nftables-table-nat', type=str, help='nat table to be used for nat chains (vyos: defaults to vyos_nat)')
    parser.add_argument('--nftables-chain-input', type=str, help='use custom chain for input, used for local services allow rules (nftables: defaults to INPUT , vyos: defaults to NAME_IN-KnockPort)')
    parser.add_argument('--nftables-chain-forward', type=str, help='use custom chain for forward, used for non-local services allow rules (nftables: defaults to FORWARD , vyos: defaults to NAME_FWD-KnockPort)')
    parser.add_argument('--nftables-chain-default-input', type=str, help='chain hooked to input, used for KnockPort http/https access')
    parser.add_argument('--nftables-chain-default-output', type=str, help='chain hooked to output, used for KnockPort http/https access')
    parser.add_argument('--nftables-chain-default-forward', type=str, help='chain hooked to forward, used for non-local services access')
    parser.add_argument('--nftables-chain-default-prerouting', type=str, help='chain hooked to nat prerouting, used for non-local services access')
    parser.add_argument('--nftables-chain-default-postrouting', type=str, help='chain hooked to nat postrouting, used for non-local services access')
    parser.add_argument('--service-rule-cleanup-on-shutdown', action='store_false', default=True, help='Drop access also to services ports in addition to management (HTTP/HTTPS) ports when KnockPort is shut down. Default is to keep service port rules as is to not disrupt the services access when restarting KnockPort')
    return parser.parse_args()
