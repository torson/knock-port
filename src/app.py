import json
import os
import threading
import time
from collections import defaultdict
import ipaddress
from flask import Flask, request, abort
from config import load_config
from flask_limiter import Limiter
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import Optional, DataRequired, Length
import warnings
from threading import Thread, Lock
from utils import log, log_err, execute_command_with_pipes
from sessions import manage_sessions, monitor_stealthy_ports
from firewall import add_iptables_rule, add_nftables_rule

# Suppress specific warnings
warnings.filterwarnings("ignore", category=UserWarning, module='flask_limiter.extension')

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False
app.config.setdefault('trusted_waf_networks', [])

# Token cache structure: {access_key: [(token, timestamp), ...]}
token_cache = defaultdict(list)
TOKEN_CACHE_WINDOW = 60  # seconds

def _validate_ip(value: str, source: str):
    candidate = value.strip() if value else value
    if not candidate:
        log_err(f"{source} missing")
        abort(503)
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        log_err(f"Invalid {source} '{value}'")
        abort(503)

def get_client_ip():
    # Resolve the originating client IP
    trusted_waf_networks = app.config.get('trusted_waf_networks', [])
    remote_ip = _validate_ip(request.remote_addr, "remote address")

    if not trusted_waf_networks:
        return str(remote_ip)

    if not any(remote_ip in network for network in trusted_waf_networks):
        log_err(f"Rejecting request from untrusted WAF address '{remote_ip}' while --waf-trusted-ips is configured")
        abort(503)

    x_real_ip = request.headers.get('X-Real-IP', '')
    if x_real_ip.strip():
        return str(_validate_ip(x_real_ip, "X-Real-IP header"))

    x_forwarded_for = request.headers.get('X-Forwarded-For', '')
    if x_forwarded_for:
        forwarded_ips = [ip.strip() for ip in x_forwarded_for.split(',') if ip.strip()]
        if forwarded_ips:
            candidate = forwarded_ips[-1]
            return str(_validate_ip(candidate, "X-Forwarded-For header"))

    log_err("Trusted WAF request missing client IP headers (X-Real-IP/X-Forwarded-For)")
    abort(503)

def cleanup_token_cache():
    # Remove tokens older than TOKEN_CACHE_WINDOW seconds
    current_time = time.time()
    for access_key in token_cache:
        token_cache[access_key] = [
            (token, timestamp)
            for token, timestamp in token_cache[access_key]
            if current_time - timestamp < TOKEN_CACHE_WINDOW
        ]

limiter = Limiter(
    key_func=get_client_ip,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

import pyotp
from pathlib import Path

class RequestForm(FlaskForm):
    app = StringField('app', validators=[DataRequired(), Length(min=1, max=50)])
    access_key = StringField('access_key', validators=[DataRequired(), Length(min=10, max=50)])
    token = StringField('token', validators=[Optional(), Length(min=6, max=6)])

def handle_request(config, sessions, lock, session_file, access_key_type, args):
    client_ip = get_client_ip()
    form = RequestForm(request.form)
    if not form.validate():
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                print(f"Error in {fieldName}: {err}")
        abort(400, 'Invalid data format received')

    app_name = form.app.data
    access_key = form.access_key.data

    if app_name == config['global']['healthcheck_app_name']:
        # not logging healthcheck requests
        return '', 200

    log(f"Received {request.method} request from {client_ip} , data: {dict(request.form)}")
    # log(f"Parsed form data - App: {app_name}, Access Key: {access_key}")

    if app_name in config and app_name != "global" and access_key in config[app_name][f'access_key_{access_key_type}']:
        if access_key_type == "http":
            # For HTTP requests, verify 2FA token
            # Check if 2FA is configured for this access key
            tfa_config_file = Path(f"{config['global']['2fa_config_folder']}/{access_key}.json")
            if tfa_config_file.exists():
                if form.token:
                    token = form.token.data

                    # Clean up expired tokens
                    cleanup_token_cache()
                    # Check if token was recently used
                    # a valid token can be used only once to prevent an attacker repeating the same request from another IP
                    for used_token, _ in token_cache[access_key]:
                        if used_token == token:
                            log_err(f"Token '{token}' reuse attempt for access key: {access_key}")
                            abort(503)

                    # Load 2FA configuration
                    with open(tfa_config_file) as f:
                        tfa_config = json.load(f)

                    # Verify TOTP token with custom interval
                    totp = pyotp.TOTP(tfa_config['secret'], interval=tfa_config.get('interval', 30))
                    if not totp.verify(token):
                        log_err(f"Invalid 2FA token '{token}' for access key: {access_key}")
                        abort(503)

                    # Store valid token in cache
                    token_cache[access_key].append((token, time.time()))
                else:
                    log_err(f"2FA token required but not provided for access key: {access_key}")
                    abort(503)

        interface_ext = config[app_name].get('interface_ext', config['global']['interface_ext'])
        interface_int = config[app_name].get('interface_int', config['global']['interface_int'])
        port_to_open = config[app_name]['port']
        if access_key_type == "http":
            if config[app_name]['step2_https_duration']:
                duration = config[app_name]['step2_https_duration']
            else:
                duration = 60
            protocol = "tcp"
            waf_https_port = getattr(args, 'waf_https_port', None)
            port_to_open = waf_https_port if waf_https_port else args.https_port
            log(f"Opening https port {port_to_open} for {client_ip} on {interface_ext} for 5s")
        else:
            duration = config[app_name]['duration']
            protocol = config[app_name]['protocol']
            destination = config[app_name]['destination']
            destination_parts = destination.split(':')
            destination_ip = destination_parts[0]
            destination_port = destination_parts[1] if len(destination_parts) > 1 else port_to_open
            log(f"Opening service {app_name} {protocol} port {port_to_open} for {client_ip} on {interface_ext} to destination {destination} for {duration}s")

        commands = []
        if args.firewall_type == 'iptables':
            if config[app_name]['destination'] == "local":
                commands.append(f"iptables -I INPUT -i {interface_ext} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}'")
            else:
                if access_key_type == "http":
                    commands.append(f"iptables -I INPUT -i {interface_ext} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}'")
                else:
                    commands.append(f"iptables -I FORWARD -o {interface_int} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-FWD-KnockPort-{interface_int}-{app_name}-{protocol}-{port_to_open}-{client_ip}'")
                    commands.append(f"iptables -t nat -A PREROUTING -i {interface_ext} -p {protocol} -s {client_ip} --dport {port_to_open} -j DNAT --to-destination {destination_ip}:{destination_port} -m comment --comment 'ipv4-PREROUTING-KnockPort-{interface_ext}-{app_name}-{protocol}-{client_ip}-{port_to_open}-{destination_ip}-{destination_port}-DNAT'")
            for command in commands:
                add_iptables_rule(command, use_sudo=args.use_sudo)
        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
            if config[app_name]['destination'] == "local":
                commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface_ext} counter accept comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'")
            else:
                if access_key_type == "http":
                    commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface_ext} counter accept comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'")
                else:
                    commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_forward} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} oifname {interface_int} counter accept comment 'ipv4-FWD-KnockPort-{interface_int}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'")
                    nft_rule = f"{protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface_ext} counter dnat to {destination_ip}:{destination_port} comment 'ipv4-PREROUTING-KnockPort-{interface_ext}-{app_name}-{protocol}-{client_ip}-{port_to_open}-{destination_ip}-{destination_port}-DNAT'"
                    if args.firewall_type == 'nftables':
                        try:
                            output_lines_count = execute_command_with_pipes(command=f"nft list chain {args.nftables_table_nat} {args.nftables_chain_default_prerouting}", command2="wc -l", print_command=False, print_output=False, use_sudo=args.use_sudo).strip()
                        except Exception:
                            output_lines_count = "0"
                        if output_lines_count == "5" :
                            # chain empty
                            commands.append(f"nft add rule ip {args.nftables_table_nat} {args.nftables_chain_default_prerouting} {nft_rule}")
                        else:
                            commands.append(f"nft insert rule ip {args.nftables_table_nat} {args.nftables_chain_default_prerouting} index 0 {nft_rule}")
                    elif args.firewall_type == 'vyos' :
                        # vyos nft chains are never empty
                        commands.append(f"nft insert rule ip {args.nftables_table_nat} {args.nftables_chain_default_prerouting} index 0 {nft_rule}")
            for command in commands:
                add_nftables_rule(command, use_sudo=args.use_sudo)

        for command in commands:
            session_exists = False
            expires_at = time.time() + duration
            for session in sessions:
                if session['command'] == command:
                    log("Session is duplicate, updating 'expires_at'")
                    session['expires_at'] = expires_at
                    session_exists = True
                    break
            if not session_exists:
                sessions.append({'command': command, 'expires_at': expires_at})
            with lock:
                with open(session_file, 'w') as f:
                    json.dump(sessions, f, indent=4, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
    else:
        log_err(f"Unauthorized access attempt or invalid app credentials for App: {app_name}, Access Key: {access_key}")
        abort(503)
    return '', 200

def create_app(config_path, session_file, args):
    config = load_config(config_path)
    app.config['config'] = config
    app.config['service_rule_cleanup_on_shutdown'] = args.service_rule_cleanup_on_shutdown
    trusted_waf_networks = []
    raw_trusted = getattr(args, 'waf_trusted_ips', None)
    if raw_trusted:
        for entry in raw_trusted.split(','):
            entry = entry.strip()
            if not entry:
                continue
            try:
                trusted_waf_networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                log_err(f"Invalid --waf-trusted-ips entry '{entry}'. Aborting startup.")
                raise SystemExit(1)
    app.config['trusted_waf_networks'] = trusted_waf_networks
    sessions = []
    lock = Lock()

    try:
        with open(session_file, 'r') as f:
            sessions = json.load(f)
    except FileNotFoundError:
        log("No existing session file found. Starting fresh.")

    session_manager = Thread(target=manage_sessions, args=(session_file, sessions, lock, args.firewall_type, args))
    session_manager.daemon = True
    session_manager.start()

    stop_event = threading.Event()
    stealthy_ports_monitor = Thread(target=monitor_stealthy_ports, args=(config, stop_event, session_file, args, app))
    app.config['stop_event'] = stop_event
    stealthy_ports_monitor.daemon = True
    stealthy_ports_monitor.start()

    @app.route(config['global']['http_post_path'], methods=['POST'])
    # rate limit for this specific route
    @limiter.limit(f"{config['global']['step1_2_rate_limit_per_minute']} per minute")
    def handle_http_request():
        # log(f"Received HTTP {request.method} request from {request.remote_addr}")
        if request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'http', args)

    @app.route(config['global']['https_post_path'], methods=['POST'])
    # rate limit for this specific route
    @limiter.limit(f"{config['global']['step1_2_rate_limit_per_minute']} per minute")
    def handle_https_request():
        # log(f"Received HTTPS {request.method} request from {request.remote_addr}")
        if request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'https', args)

    @app.errorhandler(500)
    def handle_500(error):
        log("Server Error 500")
        abort(503)

    app.config['sessions'] = sessions
    return app
