import argparse
from utils import log
from firewall import check_config_destinations_nonlocal

def parse_args():
    parser = argparse.ArgumentParser(description="Server Application")
    parser.add_argument('-c', '--config', type=str, default='config.yaml', 
                      help='Path to the configuration file. If omitted, `config.yaml` in the current directory is used by default')
    parser.add_argument('--http-port', type=int, default=8080,
                      help='Port to run the HTTP server on (default: 8080)')
    parser.add_argument('--https-port', type=int, default=8443,
                      help='Port to run the HTTPS server on (default: 8443)')
    parser.add_argument('--cert', type=str,
                      help='Path to the TLS certificate file. This can be server certificate alone, or a bundle of (1) server, (2) intermediary and (3) root CA certificate, in this order, like TLS expects it')
    parser.add_argument('--key', type=str,
                      help='Path to the TLS key file')
    parser.add_argument('--firewall-type', type=str, default='iptables',
                      choices=['iptables', 'nftables', 'vyos'],
                      help='Type of routing to use (default: iptables)')
    parser.add_argument('--nftables-table-filter', type=str,
                      help='filter table to be used for filter chains (vyos: defaults to vyos_filter)')
    parser.add_argument('--nftables-table-nat', type=str,
                      help='nat table to be used for nat chains (vyos: defaults to vyos_nat)')
    parser.add_argument('--nftables-chain-input', type=str,
                      help='use custom chain for input, used for local services allow rules (nftables: defaults to INPUT , vyos: defaults to NAME_IN-KnockPort)')
    parser.add_argument('--nftables-chain-forward', type=str,
                      help='use custom chain for forward, used for non-local services allow rules (nftables: defaults to FORWARD , vyos: defaults to NAME_FWD-KnockPort)')
    parser.add_argument('--nftables-chain-default-input', type=str,
                      help='chain hooked to input, used for KnockPort http/https access')
    parser.add_argument('--nftables-chain-default-output', type=str,
                      help='chain hooked to output, used for KnockPort http/https access')
    parser.add_argument('--nftables-chain-default-forward', type=str,
                      help='chain hooked to forward, used for non-local services access')
    parser.add_argument('--nftables-chain-default-prerouting', type=str,
                      help='chain hooked to nat prerouting, used for non-local services access')
    parser.add_argument('--nftables-chain-default-postrouting', type=str,
                      help='chain hooked to nat postrouting, used for non-local services access')
    parser.add_argument('--service-rule-cleanup-on-shutdown',
                      action='store_false', default=True,
                      help='Drop access also to services ports in addition to management (HTTP/HTTPS) ports when KnockPort is shut down. Default is to keep service port rules as is to not disrupt the services access when restarting KnockPort')
    return parser.parse_args()

def init_vars(args, config):
    if args.firewall_type == 'nftables':
        if not args.nftables_table_filter:
            args.nftables_table_filter = "filter"
        log(f"nftables_table_filter = {args.nftables_table_filter}")
        if not args.nftables_chain_input:
            args.nftables_chain_input = "INPUT"
        log(f"nftables_chain_input = {args.nftables_chain_input}")
        if not args.nftables_chain_default_input:
            args.nftables_chain_default_input = "INPUT"
        log(f"nftables_chain_default_input = {args.nftables_chain_default_input}")
        if not args.nftables_chain_default_output:
            args.nftables_chain_default_output = "OUTPUT"
        log(f"nftables_chain_default_output = {args.nftables_chain_default_output}")
        if not args.nftables_chain_forward:
            args.nftables_chain_forward = "FORWARD"
        log(f"nftables_chain_forward = {args.nftables_chain_forward}")
        if not args.nftables_chain_default_forward:
            args.nftables_chain_default_forward = "FORWARD"
        log(f"nftables_chain_default_forward = {args.nftables_chain_default_forward}")

        if not args.nftables_table_nat:
            args.nftables_table_nat = "nat"
        log(f"nftables_table_nat = {args.nftables_table_nat}")
        if not args.nftables_chain_default_prerouting:
            args.nftables_chain_default_prerouting = "PREROUTING"
        log(f"nftables_chain_default_prerouting = {args.nftables_chain_default_prerouting}")
        if not args.nftables_chain_default_postrouting:
            args.nftables_chain_default_postrouting = "POSTROUTING"
        log(f"nftables_chain_default_postrouting = {args.nftables_chain_default_postrouting}")

    elif args.firewall_type == 'vyos':
        if not args.nftables_table_filter:
            args.nftables_table_filter = "vyos_filter"
        log(f"nftables_table_filter = {args.nftables_table_filter}")
        if not args.nftables_chain_input:
            args.nftables_chain_input = "NAME_In-KnockPort"
        nftables_chain_input = args.nftables_chain_input[len("NAME_"):]
        if not args.nftables_chain_forward:
            args.nftables_chain_forward = "NAME_FWD-KnockPort"
        nftables_chain_forward = args.nftables_chain_forward[len("NAME_"):]
        if check_config_destinations_nonlocal(config):
            log(f"nftables_chain_forward = {args.nftables_chain_forward}")
        log(f"nftables_chain_input = {args.nftables_chain_input}")
        if not args.nftables_chain_default_input:
            args.nftables_chain_default_input = "VYOS_INPUT_filter"
        log(f"nftables_chain_default_input = {args.nftables_chain_default_input}")
        if not args.nftables_chain_default_output:
            args.nftables_chain_default_output = "VYOS_OUTPUT_filter"
        log(f"nftables_chain_default_output = {args.nftables_chain_default_output}")
        if not args.nftables_chain_default_forward:
            args.nftables_chain_default_forward = "VYOS_FORWARD_filter"
        log(f"nftables_chain_default_forward = {args.nftables_chain_default_forward}")

        if not args.nftables_table_nat:
            args.nftables_table_nat = "vyos_nat"
        log(f"nftables_table_nat = {args.nftables_table_nat}")
        if not args.nftables_chain_default_prerouting:
            args.nftables_chain_default_prerouting = "PREROUTING"
        log(f"nftables_chain_default_prerouting = {args.nftables_chain_default_prerouting}")
        if not args.nftables_chain_default_postrouting:
            args.nftables_chain_default_postrouting = "POSTROUTING"
        log(f"nftables_chain_default_postrouting = {args.nftables_chain_default_postrouting}")
