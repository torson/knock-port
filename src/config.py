import yaml
import sys
import re
from utils import log, log_err

def _validate_port(port, field_name):
    """Validate port number (1-65535)"""
    if not isinstance(port, int):
        log(f"Error: config {field_name} must be an integer")
        sys.exit(1)
    if port < 1 or port > 65535:
        log(f"Error: config {field_name} must be between 1 and 65535, got {port}")
        sys.exit(1)

def _validate_positive_integer(value, field_name):
    """Validate positive integer"""
    if not isinstance(value, int):
        log(f"Error: config {field_name} must be an integer")
        sys.exit(1)
    if value <= 0:
        log(f"Error: config {field_name} must be a positive integer, got {value}")
        sys.exit(1)

def _validate_non_empty_string(value, field_name):
    """Validate non-empty string"""
    if not isinstance(value, str):
        log(f"Error: config {field_name} must be a string")
        sys.exit(1)
    if not value.strip():
        log(f"Error: config {field_name} must not be empty")
        sys.exit(1)

def _validate_access_key_list(access_keys, field_name):
    """Validate access key list"""
    if not isinstance(access_keys, list):
        log(f"Error: config {field_name} must be a list")
        sys.exit(1)
    if len(access_keys) == 0:
        log(f"Error: config {field_name} must contain at least one access key")
        sys.exit(1)
    for i, key in enumerate(access_keys):
        if not isinstance(key, str):
            log(f"Error: config {field_name}[{i}] must be a string")
            sys.exit(1)
        if not key.strip():
            log(f"Error: config {field_name}[{i}] must not be empty")
            sys.exit(1)

def _validate_destination(destination, field_name):
    """Validate destination: 'local' or IP:PORT format"""
    if not isinstance(destination, str):
        log(f"Error: config {field_name} must be a string")
        sys.exit(1)
    if destination == "local":
        return
    # Validate IP:PORT format
    # Pattern: IP address (IPv4) followed by optional :PORT
    ip_port_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
    if not re.match(ip_port_pattern, destination):
        log(f"Error: config {field_name} must be 'local' or IP:PORT format (e.g., '192.168.0.40:80' or '192.168.0.40'), got '{destination}'")
        sys.exit(1)
    # Validate IP address components
    parts = destination.split(':')
    ip_parts = parts[0].split('.')
    for part in ip_parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                log(f"Error: config {field_name} contains invalid IP address component '{part}' (must be 0-255)")
                sys.exit(1)
        except ValueError:
            log(f"Error: config {field_name} contains invalid IP address component '{part}'")
            sys.exit(1)
    # Validate port if present
    if len(parts) == 2:
        try:
            port = int(parts[1])
            if port < 1 or port > 65535:
                log(f"Error: config {field_name} contains invalid port '{port}' (must be 1-65535)")
                sys.exit(1)
        except ValueError:
            log(f"Error: config {field_name} contains invalid port '{parts[1]}'")
            sys.exit(1)

def _validate_protocol(protocol, field_name):
    """Validate protocol: 'tcp' or 'udp'"""
    if not isinstance(protocol, str):
        log(f"Error: config {field_name} must be a string")
        sys.exit(1)
    if protocol not in ['tcp', 'udp']:
        log(f"Error: config {field_name} must be 'tcp' or 'udp', got '{protocol}'")
        sys.exit(1)

def load_config(config_path):
    log("Loading configuration...")
    with open(config_path, 'r') as config_file:
        config = yaml.safe_load(config_file)

    # Validate config structure
    if not isinstance(config, dict):
        log("Error: config file must contain a YAML dictionary")
        sys.exit(1)

    if 'global' not in config:
        log("Error: config file must contain a 'global' section")
        sys.exit(1)

    if not isinstance(config['global'], dict):
        log("Error: config global section must be a dictionary")
        sys.exit(1)

    # Validate global section
    global_config = config['global']

    # Validate http_post_path and https_post_path
    post_paths = [
        ('http_post_path', '/1-SECRET'),
        ('https_post_path', '/2-SECRET')
    ]
    allowed_http_path_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~")
    for field_name, default_value in post_paths:
        if field_name not in global_config:
            log(f"Error: config global.{field_name} is required")
            sys.exit(1)
        post_path = global_config[field_name]
        if post_path == default_value:
            log(f"Error: config global.{field_name} must not be default value '{default_value}'")
            sys.exit(1)
        try:
            post_path_bytes = post_path.encode("ascii")
        except UnicodeEncodeError:
            log(f"Error: config global.{field_name} must contain only ASCII characters")
            sys.exit(1)
        if not post_path.startswith("/"):
            log(f"Error: config global.{field_name} must start with '/'")
            sys.exit(1)
        if len(post_path_bytes) < 2:
            log(f"Error: config global.{field_name} must include at least one character after '/'")
            sys.exit(1)
        if len(post_path_bytes) > 11:
            log(f"Error: config global.{field_name} total length (including leading '/') must not exceed 11 ASCII characters due to firewall limits")
            sys.exit(1)
        disallowed_chars = set(post_path[1:]) - allowed_http_path_chars
        if disallowed_chars:
            log(f"Error: config global.{field_name} contains unsupported characters {sorted(disallowed_chars)}; allowed characters are [A-Za-z0-9-_.~]")
            sys.exit(1)

    # Validate step1_2_rate_limit_per_minute
    if 'step1_2_rate_limit_per_minute' not in global_config:
        log("Error: config global.step1_2_rate_limit_per_minute is required")
        sys.exit(1)
    _validate_positive_integer(global_config['step1_2_rate_limit_per_minute'], 'global.step1_2_rate_limit_per_minute')

    # Validate interface_ext
    if 'interface_ext' not in global_config:
        log("Error: config global.interface_ext is required")
        sys.exit(1)
    _validate_non_empty_string(global_config['interface_ext'], 'global.interface_ext')

    # Validate interface_int
    if 'interface_int' not in global_config:
        log("Error: config global.interface_int is required")
        sys.exit(1)
    _validate_non_empty_string(global_config['interface_int'], 'global.interface_int')

    # Validate 2fa_config_folder
    if '2fa_config_folder' not in global_config:
        log("Error: config global.2fa_config_folder is required")
        sys.exit(1)
    _validate_non_empty_string(global_config['2fa_config_folder'], 'global.2fa_config_folder')

    # Validate healthcheck_app_name
    if 'healthcheck_app_name' not in global_config:
        log("Error: config global.healthcheck_app_name is required")
        sys.exit(1)
    _validate_non_empty_string(global_config['healthcheck_app_name'], 'global.healthcheck_app_name')

    # Validate service sections
    for service_name, service_config in config.items():
        if service_name == 'global':
            continue

        if not isinstance(service_config, dict):
            log(f"Error: config {service_name} must be a dictionary")
            sys.exit(1)

        # Validate port
        if 'port' not in service_config:
            log(f"Error: config {service_name}.port is required")
            sys.exit(1)
        _validate_port(service_config['port'], f'{service_name}.port')

        # Validate access_key_http
        if 'access_key_http' not in service_config:
            log(f"Error: config {service_name}.access_key_http is required")
            sys.exit(1)
        _validate_access_key_list(service_config['access_key_http'], f'{service_name}.access_key_http')

        # Validate access_key_https
        if 'access_key_https' not in service_config:
            log(f"Error: config {service_name}.access_key_https is required")
            sys.exit(1)
        _validate_access_key_list(service_config['access_key_https'], f'{service_name}.access_key_https')

        # Validate destination
        if 'destination' not in service_config:
            log(f"Error: config {service_name}.destination is required")
            sys.exit(1)
        _validate_destination(service_config['destination'], f'{service_name}.destination')

        # Validate protocol
        if 'protocol' not in service_config:
            log(f"Error: config {service_name}.protocol is required")
            sys.exit(1)
        _validate_protocol(service_config['protocol'], f'{service_name}.protocol')

        # Validate duration
        if 'duration' not in service_config:
            log(f"Error: config {service_name}.duration is required")
            sys.exit(1)
        _validate_positive_integer(service_config['duration'], f'{service_name}.duration')

        # Validate step2_https_duration
        if 'step2_https_duration' not in service_config:
            log(f"Error: config {service_name}.step2_https_duration is required")
            sys.exit(1)
        _validate_positive_integer(service_config['step2_https_duration'], f'{service_name}.step2_https_duration')

        # Validate optional interface_ext
        if 'interface_ext' in service_config:
            _validate_non_empty_string(service_config['interface_ext'], f'{service_name}.interface_ext')

        # Validate optional interface_int
        if 'interface_int' in service_config:
            _validate_non_empty_string(service_config['interface_int'], f'{service_name}.interface_int')

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
