import yaml
import sys
from utils import log, log_err

def load_config(config_path):
    log("Loading configuration...")
    with open(config_path, 'r') as config_file:
        config = yaml.safe_load(config_file)
    # config validation
    if config['global']['http_post_path'] == "/1-SECRET":
        log("Error: config global.http_post_path must not be default value '/1-SECRET'")
        sys.exit(1)
    if config['global']['https_post_path'] == "/2-SECRET":
        log("Error: config global.https_post_path must not be default value '/2-SECRET'")
        sys.exit(1)
    return config

def check_config_destinations_nonlocal(config):
    # Check if any services have non-local destinations
    non_local_services = []
    for service_name, settings in config.items():
        if service_name != "global":
            destination = settings.get('destination')
            if destination != 'local':
                non_local_services.append((service_name, destination))
    return non_local_services

def init_vars(args, config):
    if args.firewall_type == 'nftables':
        if not args.nftables_table_filter:
            # table filter is used on Debian so we set it as default
            args.nftables_table_filter = "filter"
        log(f"nftables_table_filter = {args.nftables_table_filter}")
        if not args.nftables_chain_input:
            # chain used for KnockPort service allow rules
            args.nftables_chain_input = "INPUT"
        log(f"nftables_chain_input = {args.nftables_chain_input}")
        if not args.nftables_chain_default_input:
            # chain INPUT is used on Debian so we set it as default
            args.nftables_chain_default_input = "INPUT"
        log(f"nftables_chain_default_input = {args.nftables_chain_default_input}")
        if not args.nftables_chain_default_output:
            # chain OUTPUT is used on Debian so we set it as default
            args.nftables_chain_default_output = "OUTPUT"
        log(f"nftables_chain_default_output = {args.nftables_chain_default_output}")
        if not args.nftables_chain_forward:
            # chain FORWARD is used on Debian so we set it as default
            args.nftables_chain_forward = "FORWARD"
        log(f"nftables_chain_forward = {args.nftables_chain_forward}")
        if not args.nftables_chain_default_forward:
            # chain FORWARD is used on Debian so we set it as default
            args.nftables_chain_default_forward = "FORWARD"
        log(f"nftables_chain_default_forward = {args.nftables_chain_default_forward}")

        if not args.nftables_table_nat:
            # table filter is used on Debian so we set it as default
            args.nftables_table_nat = "nat"
        log(f"nftables_table_nat = {args.nftables_table_nat}")
        if not args.nftables_chain_default_prerouting:
            # chain used for KnockPort service allow rules
            args.nftables_chain_default_prerouting = "PREROUTING"
        log(f"nftables_chain_default_prerouting = {args.nftables_chain_default_prerouting}")
        if not args.nftables_chain_default_postrouting:
            # chain INPUT is used on Debian so we set it as default
            args.nftables_chain_default_postrouting = "POSTROUTING"
        log(f"nftables_chain_default_postrouting = {args.nftables_chain_default_postrouting}")

    if args.firewall_type == 'vyos':
        if not args.nftables_table_filter:
            # table vyos_filter is used on VyOs so we set it as default
            args.nftables_table_filter = "vyos_filter"
        log(f"nftables_table_filter = {args.nftables_table_filter}")
        if not args.nftables_chain_input:
            # chain used for KnockPort service allow rules
            # if you add a chain IN-KnockPort with 'set firewall ipv4 name IN-KnockPort' then that is set into table vyos_filter (check with 'nft list ruleset')
            # and the actual name of the chain becomes NAME_IN-KnockPort
            args.nftables_chain_input = "NAME_IN-KnockPort"
        nftables_chain_input = args.nftables_chain_input[len("NAME_"):]
        if not args.nftables_chain_forward:
            # chain used for KnockPort service allow rules
            # if you add a chain FWD-KnockPort with 'set firewall ipv4 name FWD-KnockPort' then that is set into table vyos_filter (check with 'nft list ruleset')
            # and the actual name of the chain becomes NAME_FWD-KnockPort
            args.nftables_chain_forward = "NAME_FWD-KnockPort"
        nftables_chain_forward = args.nftables_chain_forward[len("NAME_"):]
        if check_config_destinations_nonlocal(config):
            log(f"nftables_chain_forward = {args.nftables_chain_forward}")
        log(f"nftables_chain_input = {args.nftables_chain_input}")
        if not args.nftables_chain_default_input:
            # chain VYOS_INPUT_filter is used on VyOs so we set it as default
            args.nftables_chain_default_input = "VYOS_INPUT_filter"
        log(f"nftables_chain_default_input = {args.nftables_chain_default_input}")
        if not args.nftables_chain_default_output:
            # chain VYOS_OUTPUT_filter is used on VyOs so we set it as default
            args.nftables_chain_default_output = "VYOS_OUTPUT_filter"
        log(f"nftables_chain_default_output = {args.nftables_chain_default_output}")
        if not args.nftables_chain_default_forward:
            # chain VYOS_FORWARD_filter is used on VyOs so we set it as default
            args.nftables_chain_default_forward = "VYOS_FORWARD_filter"
        log(f"nftables_chain_default_forward = {args.nftables_chain_default_forward}")

        if not args.nftables_table_nat:
            # table filter is used on Debian so we set it as default
            args.nftables_table_nat = "vyos_nat"
        log(f"nftables_table_nat = {args.nftables_table_nat}")
        if not args.nftables_chain_default_prerouting:
            # chain used for KnockPort service allow rules
            args.nftables_chain_default_prerouting = "PREROUTING"
        log(f"nftables_chain_default_prerouting = {args.nftables_chain_default_prerouting}")
        if not args.nftables_chain_default_postrouting:
            # chain INPUT is used on Debian so we set it as default
            args.nftables_chain_default_postrouting = "POSTROUTING"
        log(f"nftables_chain_default_postrouting = {args.nftables_chain_default_postrouting}")

