
import argparse
import yaml
import time
import sys
import signal
from flask import Flask, request, abort
from werkzeug.serving import make_server
from threading import Thread, Lock
import json
import subprocess
import os
from subprocess import Popen, PIPE
import re
import os
from pprint import pprint
import pprint
from sh import bash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Length, AnyOf

app = Flask(__name__)
# app.config['SECRET_KEY'] = 'e49d5ffb-6d19-467b-bd5f-ade35f7f68d3'  # Needed for CSRF protection
app.config['WTF_CSRF_ENABLED'] = False

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

pp = pprint.PrettyPrinter(indent=4)

def log(text):
    message = "%s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
    print(message, end='', flush=True)

def log_err(text):
    message = "%s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
    print(message, end='', file=sys.stderr, flush=True)

def load_config(config_path):
    log("Loading configuration...")
    with open(config_path, 'r') as config_file:
        return yaml.safe_load(config_file)

def check_config_destinations_nonlocal(config):
    non_local_services = []
    for service_name, settings in config.items():
        destination = settings.get('destination')
        if destination != 'local':
            non_local_services.append((service_name, destination))
    return non_local_services

def execute_command(command, print_command=True, print_output=True):
    if print_command:
        log(f"Executing command: {command}")
    out=str(bash('-c', command, _tty_out=True)).strip()
    if out:
        if print_output:
            log(out)
    return out

def manage_sessions(session_file, sessions, lock):
    while True:
        current_time = time.time()
        with lock:
            if sessions is None:
                sessions = []
            expired_sessions = [s for s in sessions if current_time > s['expires_at']]
            for session in expired_sessions:
                log(f"Session expired: {session['command']}")
                command = session['command']
                sessions.remove(session)
                with open(session_file, 'w') as f:
                    json.dump(sessions, f, indent=4, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                if args.routing_type == 'iptables':
                    delete_iptables_rule(command)
                elif args.routing_type == 'nftables':
                    delete_nftables_rule(session['command'])
                elif args.routing_type == 'vyos':
                    delete_nftables_rule(session['command'])
        time.sleep(1)

def monitor_stealthy_ports(config):
    # in case there's unintended rules change that Knock-Port relies on we reapply stealthy ports setup
    time.sleep(5)
    while True:
        if args.routing_type == 'iptables':
            command = f"iptables -n -v -L | grep ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-drop ; true"
        elif args.routing_type == 'nftables' or args.routing_type == 'vyos':
            # on VyOs if you make a firewall change it will reset all chains to what is set up with set "set" commands
            # we're just checking for this one rule since it's most important
            command = f"nft -a list chain ip {args.nftables_table_filter} {args.nftables_chain_default_input} | grep ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-drop ; true"
        out = execute_command(command, print_command=False, print_output=False)
        if not out:
            log("Stealthy port rule missing, reapplying stealthy ports setup.")
            setup_stealthy_ports(config)
        time.sleep(5)

class RequestForm(FlaskForm):
    app = StringField('app', validators=[DataRequired(), Length(min=1, max=50)])
    access_key = StringField('access_key', validators=[DataRequired(), Length(min=10, max=50)])

def handle_request(config, sessions, lock, session_file, access_key_type):
    client_ip = request.remote_addr
    log(f"Received request from {client_ip}")
    form = RequestForm(request.form)
    log(f"Received data: {dict(request.form)}")
    if not form.validate():
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                print(f"Error in {fieldName}: {err}")
        abort(400, 'Invalid data format received')

    app_name = form.app.data
    access_key = form.access_key.data
    log(f"Parsed form data - App: {app_name}, Access Key: {access_key}")

    if app_name in config and app_name != "global" and access_key in config[app_name][f'access_key_{access_key_type}']:
        interface_in = config[app_name].get('interface_in', config['global']['interface_in'])
        interface_out = config[app_name].get('interface_out', config['global']['interface_out'])
        port_to_open = config[app_name]['port']
        if access_key_type == "http":
            if config[app_name]['step2_https_duration']:
                duration = config[app_name]['step2_https_duration']
            else:
                duration = 60
            protocol = "tcp"
            port_to_open = args.https_port
            log(f"Opening https port {port_to_open} for {client_ip} on {interface_in} for 5s")
        else:
            duration = config[app_name]['duration']
            protocol = config[app_name]['protocol']
            log(f"Opening service {app_name} {protocol} port {port_to_open} for {client_ip} on {interface_in} for {duration}s")
        if args.routing_type == 'iptables':
            if config[app_name]['destination'] == "local":
                command = f"iptables -I INPUT -i {interface_in} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_in}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
            else:
                if access_key_type == "http":
                    command = f"iptables -I INPUT -i {interface_in} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_in}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
                else:
                    command = f"iptables -I FORWARD -o {interface_out} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-FWD-KnockPort-{interface_out}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
            add_iptables_rule(command)
        elif args.routing_type == 'nftables' or args.routing_type == 'vyos' :
            if config[app_name]['destination'] == "local":
                command = f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface_in} counter accept comment 'ipv4-IN-KnockPort-{interface_in}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'"
            else:
                if access_key_type == "http":
                    command = f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface_in} counter accept comment 'ipv4-IN-KnockPort-{interface_in}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'"
                else:
                    command = f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_forward} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} oifname {interface_out} counter accept comment 'ipv4-FWD-KnockPort-{interface_out}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'"
            add_nftables_rule(command)
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

def create_app(config_path, session_file):
    config = load_config(config_path)
    app.config['config'] = config
    sessions = []
    lock = Lock()

    try:
        with open(session_file, 'r') as f:
            sessions = json.load(f)
    except FileNotFoundError:
        log("No existing session file found. Starting fresh.")

    session_manager = Thread(target=manage_sessions, args=(session_file, sessions, lock))
    session_manager.daemon = True
    session_manager.start()
    log(f"config_path: {config_path}")
    stealthy_ports_monitor = Thread(target=monitor_stealthy_ports, args=(config,))
    stealthy_ports_monitor.daemon = True
    stealthy_ports_monitor.start()

    @app.route(config['global']['http_post_path'], methods=['POST'])
    @limiter.limit(f"config['global']['step1_2_rate_limit_per_minute'] per minute")  # rate limit for this specific route
    def handle_http_request():
        log(f"Received HTTP {request.method} request from {request.remote_addr}")
        if request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'http')

    @app.route(config['global']['https_post_path'], methods=['POST'])
    @limiter.limit(f"config['global']['step1_2_rate_limit_per_minute'] per minute")  # rate limit for this specific route
    def handle_https_request():
        log(f"Received HTTPS {request.method} request from {request.remote_addr}")
        if request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'https')

    @app.errorhandler(500)
    def handle_500(error):
        log("Server Error 500")
        abort(503)

    app.config['sessions'] = sessions
    return app

## iptables
def iptables_rule_exists(command, output=False):
    pattern = r'^\S+\s+\S+\s+(\S+)\s+.*comment\s\'([^\']+)\''
    # log(f"iptables_rule_exists , command: {command}")
    # log(f"iptables_rule_exists , pattern: {pattern}")
    match = re.search(pattern, command)
    if match:
        table = match.group(1)
        if table == "nat":
            table = f"-t {table}"
        comment = match.group(2)
        command_rules_list = f"iptables -n -v -L {table}"
        # log(f"iptables_rule_exists , command_rules_list: {command_rules_list}")
        try:
            command = f"{command_rules_list} | grep {comment} ; true"
            # log(f"Executing command: {command}")
            rule = bash('-c', command, _tty_out=True).strip()
            if rule:
                if output:
                    log(f"Rule exists : '{rule}'")
                return True
            else:
                return False
        except Exception as e:
            log_err(f"Error during operations: {e}")
    else:
        log_err(f"iptables : regex parsing of command failed : {command}")

def add_iptables_rule(command):
    if not iptables_rule_exists(command, True):
        execute_command(command)

def delete_iptables_rule(command):
    if iptables_rule_exists(command):
        command = command.replace(' -A ', ' -D ')
        command = command.replace(' -I ', ' -D ')
        execute_command(command)

## nftables
def nftables_rule_exists(command, output=False, pattern=r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*comment\s\'([^\']+)\''):
    # searches rule comment or name
    match = re.search(pattern, command)
    if match:
        table = match.group(1)
        chain = match.group(2)
        grep_pattern = match.group(3)
        command_nft_list = f"nft -a list chain ip {table} {chain}"
        try:
            command = f"{command_nft_list} | grep {grep_pattern} | grep handle ; true"
            # log(f"Executing command: {command}")
            rule = bash('-c', command, _tty_out=True).strip()
            if rule:
                if output:
                    log(f"Rule exists : '{rule}'")
                handle = rule.split()[-1]
                return handle
            else:
                return False
        except Exception as e:
            log_err(f"Error during operations: {e}")
    else:
        log_err(f"nftables : regex parsing of command failed : {command}")

def add_nftables_rule(command):
    if not nftables_rule_exists(command, True):
        execute_command(f"{command}")

def delete_nftables_rule(command):
    if nftables_rule_exists(command):
        # with nftables you can't just replace 'add' with 'del' like it's done with iptables, it's much more complicated , you need to list all the rules of a table, find the one to delete, take the handle number and then delete that handle. Insane.
        # nft delete rule ip vyos_filter NAME_IN-OpenVPN-KnockPort handle $(nft -a list table ip vyos_filter | grep "ipv4-NAM-IN-OpenVPN-KnockPort-tmp-127.0.0.1" | grep "handle" | awk '{print $NF}')
        # Regex pattern to capture the 5th word, 6th word, and the last quoted word
        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*comment\s\'([^\']+)\''
        match = re.search(pattern, command)
        if match:
            table = match.group(1)
            chain = match.group(2)
            comment = match.group(3)
            command_nft_list = f"nft -a list table ip {table}"
            command_nft_delete = f"nft delete rule ip {table} {chain} handle"
            try:
                command = f"{command_nft_list} | grep {comment} | grep handle" + " | awk '{print $NF}'"
                log(f"Executing command: {command}")
                handle = bash('-c', command, _tty_out=True).strip()
                if handle:
                    execute_command(f"{command_nft_delete} {handle}")
                else:
                    log_err("No valid handle found.")
            except Exception as e:
                log_err(f"Error during operations: {e}")
        else:
            log_err(f"nftables : No rule match found for : {command}")


def delete_nftables_rule(command):
    if nftables_rule_exists(command):
        # with nftables you can't just replace 'add' with 'del' like it's done with iptables, it's much more complicated , you need to list all the rules of a table, find the one to delete, take the handle number and then delete that handle. Insane.
        # nft delete rule ip vyos_filter NAME_IN-OpenVPN-KnockPort handle $(nft -a list table ip vyos_filter | grep "ipv4-NAM-IN-OpenVPN-KnockPort-tmp-127.0.0.1" | grep "handle" | awk '{print $NF}')
        # Regex pattern to capture the 5th word, 6th word, and the last quoted word
        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*comment\s\'([^\']+)\''
        match = re.search(pattern, command)
        if match:
            table = match.group(1)
            chain = match.group(2)
            comment = match.group(3)
            command_nft_list = f"nft -a list table ip {table}"
            command_nft_delete = f"nft delete rule ip {table} {chain} handle"
            try:
                command = f"{command_nft_list} | grep {comment} | grep handle" + " | awk '{print $NF}'"
                log(f"Executing command: {command}")
                handle = bash('-c', command, _tty_out=True).strip()
                if handle:
                    execute_command(f"{command_nft_delete} {handle}")
                else:
                    log_err("No valid handle found.")
            except Exception as e:
                log_err(f"Error during operations: {e}")
        else:
            log_err(f"nftables : No rule match found for : {command}")

def cleanup_firewall(sessions):
    for session in sessions:
        if args.routing_type == 'iptables':
            command = session['command'].replace(' -A ', ' -D ')
            delete_iptables_rule(command)
        elif args.routing_type == 'nftables':
            delete_nftables_rule(session['command'])
        elif args.routing_type == 'vyos':
            delete_nftables_rule(session['command'])

def apply_dnat_snat_rules(config):
    if check_config_destinations_nonlocal(config):
        log("Setting up forwarding (at least one of the configured services has non-local destination):")
        for app_name, app_config in config.items():
            if app_name != "global":
                if app_config['destination'] != "local":
                    interface_in = app_config.get('interface_in', config['global']['interface_in'])
                    interface_out = app_config.get('interface_out', config['global']['interface_out'])
                    if args.routing_type == 'iptables':
                        add_iptables_rule(f"iptables -t nat -A PREROUTING -i {interface_in} -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']} -m comment --comment 'ipv4-PREROUTING-KnockPort-{interface_in}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'")
                        add_iptables_rule(f"iptables -t nat -A POSTROUTING -o {interface_out} -p {app_config['protocol']} -d {app_config['destination']} --dport {app_config['port']} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_out}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'")
                    elif args.routing_type == 'nftables' or args.routing_type == 'vyos':
# table ip nat {
# 	chain PREROUTING {
# 		type nat hook prerouting priority dstnat; policy accept;
# 		iifname "eth0" tcp dport 1294  counter packets 3 bytes 180 dnat to 172.17.0.4:1294
# 	}

# 	chain POSTROUTING {
# 		type nat hook postrouting priority srcnat; policy accept;
# 		oifname "eth0" ip daddr 172.17.0.4 tcp dport 1294  counter packets 0 bytes 0 masquerade
# 	}
# }
                        # initialize tables and chains if missing
                        nft_list_ruleset = execute_command(f"nft list ruleset", print_command=False, print_output=False)
                        if not "table ip nat {" in nft_list_ruleset:
                            execute_command("nft add table ip nat")
                        if not "chain PREROUTING {" in nft_list_ruleset:
                            execute_command("nft add chain ip nat PREROUTING '{ type nat hook prerouting priority filter; policy accept; }'")
                        if not "chain POSTROUTING {" in nft_list_ruleset:
                            execute_command("nft add chain ip nat POSTROUTING '{ type nat hook postrouting priority filter; policy accept; }'")

                        output_lines_count = execute_command(f"nft list chain {args.nftables_table_nat} {args.nftables_chain_default_prerouting} | wc -l", print_command=False, print_output=False)
                        if output_lines_count == "5" :
                            # chain empty
                            add_nftables_rule(f"nft add rule ip {args.nftables_table_nat} {args.nftables_chain_default_prerouting} {app_config['protocol']} dport {app_config['port']} iifname {interface_in} counter dnat to {app_config['destination']}:{app_config['port']} comment 'ipv4-PREROUTING-KnockPort-{interface_in}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'")
                        else:
                            add_nftables_rule(f"nft insert rule ip {args.nftables_table_nat} {args.nftables_chain_default_prerouting} index 0 {app_config['protocol']} dport {app_config['port']} iifname {interface_in} counter dnat to {app_config['destination']}:{app_config['port']} comment 'ipv4-PREROUTING-KnockPort-{interface_in}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'")

                        output_lines_count = execute_command(f"nft list chain {args.nftables_table_nat} {args.nftables_chain_default_postrouting} | wc -l", print_command=False, print_output=False)
                        if output_lines_count == "5" :
                            # chain empty
                            add_nftables_rule(f"nft add rule ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting} {app_config['protocol']} dport {app_config['port']} ip daddr {app_config['destination']} oifname {interface_out} counter masquerade comment 'ipv4-POSTROUTING-KnockPort-{interface_out}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'")
                        else:
                            add_nftables_rule(f"nft insert rule ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting} index 0 {app_config['protocol']} dport {app_config['port']} ip daddr {app_config['destination']} oifname {interface_out} counter masquerade comment 'ipv4-POSTROUTING-KnockPort-{interface_out}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'")

# table ip vyos_nat {
# 	chain PREROUTING {
# 		type nat hook prerouting priority dstnat; policy accept;
# 		counter packets 1294214 bytes 92934875 jump VYOS_PRE_DNAT_HOOK
# 		iifname "eth0" tcp dport 3306 counter packets 133 bytes 7980 dnat to 172.35.1.52:3306 comment "DST-NAT-101"
# 	}

# 	chain POSTROUTING {
# 		type nat hook postrouting priority srcnat; policy accept;
# 		counter packets 1201507 bytes 82001110 jump VYOS_PRE_SNAT_HOOK
# 		oifname "eth0" ip saddr 10.100.1.0/24 ip daddr 172.0.0.0/8 counter packets 1167697 bytes 79037721 masquerade comment "SRC-NAT-101"
# 		oifname "eth0" ip saddr 10.100.1.0/24 ip daddr 10.0.0.0/8 counter packets 74 bytes 4484 masquerade comment "SRC-NAT-102"
# 		oifname "eth0" ip saddr 10.100.1.248/29 ip daddr 0.0.0.0/0 counter packets 0 bytes 0 masquerade comment "SRC-NAT-103"
# 		oifname "eth0" ip saddr 172.31.1.213 ip daddr 172.35.1.52 counter packets 133 bytes 7980 masquerade comment "SRC-NAT-110"
# 	}


def cleanup_dnat_snat_rules(config):
    if check_config_destinations_nonlocal(config):
        for app_name, app_config in config.items():
            if app_name != "global":
                if app_config['destination'] != "local":
                    interface_in = app_config.get('interface_in', config['global']['interface_in'])
                    interface_out = app_config.get('interface_out', config['global']['interface_out'])
                    if args.routing_type == 'iptables':
                        delete_iptables_rule(f"iptables -t nat -A PREROUTING -i {interface_in} -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']} -m comment --comment 'ipv4-PREROUTING-KnockPort-{interface_in}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'")
                        delete_iptables_rule(f"iptables -t nat -A POSTROUTING -o {interface_out} -p {app_config['protocol']} -d {app_config['destination']} --dport {app_config['port']} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_out}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'")
                    elif args.routing_type == 'nftables' or args.routing_type == 'vyos':
                        delete_nftables_rule(f"nft add rule ip {args.nftables_table_nat} {args.nftables_chain_default_prerouting} {app_config['protocol']} dport {app_config['port']} iifname {interface_in} counter dnat to {app_config['destination']}:{app_config['port']} comment 'ipv4-PREROUTING-KnockPort-{interface_in}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'")
                        delete_nftables_rule(f"nft add rule ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting} {app_config['protocol']} daddr {app_config['destination']} dport {app_config['port']} oifname {interface_out} counter masquerade comment 'ipv4-POSTROUTING-KnockPort-{interface_out}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'")

def string_to_hex_and_bit_length(input_string):
    # Convert string to bytes, then to hexadecimal
    hex_representation = input_string.encode().hex()
    # Calculate the bit length
    bit_length = len(hex_representation) * 4  # Each hex digit represents 4 bits
    return hex_representation, bit_length

def setup_stealthy_ports(config):
    if args.routing_type == 'nftables':
        # initialize tables and chains if missing
        nft_list_ruleset = execute_command(f"nft list ruleset", print_command=False, print_output=False)
        if not "table ip filter {" in nft_list_ruleset:
            execute_command("nft add table ip filter")
        if not "chain INPUT {" in nft_list_ruleset:
            execute_command("nft add chain ip filter INPUT '{ type filter hook input priority filter; policy accept; }'")
        if not "chain OUTPUT {" in nft_list_ruleset:
            execute_command("nft add chain ip filter OUTPUT '{ type filter hook output priority filter; policy accept; }'")
        if not "chain FORWARD {" in nft_list_ruleset:
            execute_command("nft add chain ip filter FORWARD '{ type filter hook forward priority filter; policy accept; }'")

    if args.routing_type == 'nftables' or args.routing_type == 'vyos':
        stealthy_ports_commands = []
        # setting common stuff for types nftables and vyos
        # nftables doesn't have string module like iptables, so we need to match hex characters on exact positions inside the TCP packet payload
        http_post_phase1_hex_string, http_post_phase1_hex_string_bit_length = string_to_hex_and_bit_length(f"POST {app.config['config']['global']['http_post_path']}")
        output_lines_count = execute_command(f"nft list chain {args.nftables_table_filter} {args.nftables_chain_default_input} | wc -l", print_command=False, print_output=False)
        stealthy_ports_commands.append("echo Drop incoming packets to HTTP port")
        if output_lines_count == "5" :
            # chain empty
            stealthy_ports_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} tcp dport {args.http_port} iifname {config['global']['interface_in']} counter drop comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-drop'")
        else:
            stealthy_ports_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {args.http_port} iifname {config['global']['interface_in']} counter drop comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-drop'")
        stealthy_ports_commands = stealthy_ports_commands + [
            # we're adding rules with insert so the final order will be opposite of the order here
            "echo Allow incoming POST /_HTTP_PATH_ packets to HTTP port",
                # @ih,0,N from here : https://manpages.debian.org/bookworm/nftables/nft.8.en.html#RAW_PAYLOAD_EXPRESSION
                f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {args.http_port} @ih,0,{http_post_phase1_hex_string_bit_length} == 0x{http_post_phase1_hex_string} iifname {config['global']['interface_in']} counter accept comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-POST-path-{app.config['config']['global']['http_post_path'].replace('/', '_')}-accept'",
            "echo Allow incoming SYN packets to HTTP port for initial three-way TCP handshake",
                f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {args.http_port} 'tcp flags & (fin|syn|rst|ack) == syn' iifname {config['global']['interface_in']} counter accept comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-SYN-accept'",
            "echo Drop outgoing traffic from KnockPort HTTP port , allow only TCP packets for initial three-way TCP handshake so web-server is able to handle the request . Client will not receive a HTTP response",
                f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_output} tcp sport {args.http_port} oifname {config['global']['interface_out']} counter drop comment 'ipv4-OUT-KnockPort-{config['global']['interface_out']}-tcp-sport-{args.http_port}-drop'",
                f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} 'tcp flags & (syn|ack) == syn|ack' oifname {config['global']['interface_out']} counter accept comment 'ipv4-OUT-KnockPort-{config['global']['interface_out']}-tcp-sport-{args.http_port}-syn-ack-accept'"
        ]

    if args.routing_type == 'iptables':
        stealthy_ports_commands = [
            "echo Drop incoming packets to HTTP port",
                f"iptables -I INPUT -i {config['global']['interface_in']} -p tcp --dport {args.http_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-drop'",
            "echo Allow incoming POST /_HTTP_PATH_ packets to HTTP port",
                f"iptables -I INPUT -i {config['global']['interface_in']} -p tcp --dport {args.http_port} -m string --string 'POST {app.config['config']['global']['http_post_path']}' --algo bm --to 65535 -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-POST-path-{app.config['config']['global']['http_post_path'].replace('/', '_')}-accept'",
            "echo Allow incoming SYN packets to HTTP port for initial three-way TCP handshake",
                f"iptables -I INPUT -i {config['global']['interface_in']} -p tcp --dport {args.http_port} --tcp-flags ALL SYN -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.http_port}-SYN-accept'",
            "echo Drop outgoing traffic from KnockPort HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a response from HTTP port",
                f"iptables -I OUTPUT -o {config['global']['interface_out']} -p tcp --sport {args.http_port} -j DROP -m comment --comment 'ipv4-OUT-KnockPort-{config['global']['interface_out']}-tcp-sport-{args.http_port}-drop'",
                f"iptables -I OUTPUT -o {config['global']['interface_out']} -p tcp --sport {args.http_port} --tcp-flags ALL SYN,ACK -j ACCEPT -m comment --comment 'ipv4-OUT-KnockPort-{config['global']['interface_out']}-tcp-sport-{args.http_port}-syn-ack-accept'",
            "echo Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP port",
                f"iptables -I INPUT -i {config['global']['interface_in']} -p tcp --dport {args.https_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-tcp-dport-{args.https_port}-drop'"
        ]

        for app_name, app_config in config.items():
            if app_name != "global":
                if app_config['destination'] == "local":
                    stealthy_ports_commands.append("echo Drop incoming packets to Services ports")
                    stealthy_ports_commands.append(f"iptables -I INPUT -i {config['global']['interface_in']} -p {app_config['protocol']} --dport {app_config['port']} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_in']}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                else:
                    interface_in = app_config.get('interface_in', config['global']['interface_in'])
                    stealthy_ports_commands.append("echo Drop incoming packets to forwarded Services ports")
                    stealthy_ports_commands.append(f"iptables -I FORWARD -i {interface_in} -p {app_config['protocol']} --dport {app_config['port']} -j DROP -m comment --comment 'ipv4-FWD-KnockPort-{config['global']['interface_in']}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")

        for command in stealthy_ports_commands:
            if re.search(r"iptables -(A|I)", command):
                add_iptables_rule(command)
            else:
                execute_command(f"{command}", False)

    elif args.routing_type == 'nftables':
        stealthy_ports_commands = stealthy_ports_commands + [
            "echo Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP port",
                f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {args.https_port} iifname {config['global']['interface_in']} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'"
        ]
        for app_name, app_config in config.items():
            if app_name != "global":
                interface_in = app_config.get('interface_in', config['global']['interface_in'])
                interface_out = app_config.get('interface_out', config['global']['interface_out'])
                if app_config['destination'] == "local":
                    stealthy_ports_commands.append("echo Drop incoming packets to Services ports")
                    stealthy_ports_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 {app_config['protocol']} dport {app_config['port']} iifname {interface_in} counter drop comment 'ipv4-IN-KnockPort-{interface_in}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                else:
                    stealthy_ports_commands.append("echo Drop incoming packets to forwarded Services ports")
                    output_lines_count = execute_command(f"nft list chain {args.nftables_table_filter} {args.nftables_chain_default_forward} | wc -l", print_command=False, print_output=False)
                    if output_lines_count == "5" :
                        # chain empty
                        stealthy_ports_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_forward} {app_config['protocol']} dport {app_config['port']} oifname {interface_out} counter drop comment 'ipv4-FWD-KnockPort-{interface_out}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                    else:
                        stealthy_ports_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_forward} index 0 {app_config['protocol']} dport {app_config['port']} oifname {interface_out} counter drop comment 'ipv4-FWD-KnockPort-{interface_out}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")

        for command in stealthy_ports_commands:
            if re.search(r"nft (add|insert) rule", command):
                add_nftables_rule(command)
            else:
                execute_command(f"{command}", False)

    elif args.routing_type == 'vyos':
        stealthy_ports_commands.append("echo Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP port")
        # with VyOS we're handling the jump to the separate args.nftables_chain_input
        jump_command = f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} counter jump {args.nftables_chain_input} comment 'none'"
        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+jump\s+(\S+)\s+comment\s.+'
        jump_command_handle = nftables_rule_exists(jump_command, False, pattern)
        if jump_command_handle:
            stealthy_ports_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} handle {jump_command_handle} tcp dport {args.https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'")
        else:
            stealthy_ports_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {args.https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'")

        for command in stealthy_ports_commands:
            if re.search(r"nft (add|insert) rule", command):
                add_nftables_rule(command)
            else:
                execute_command(f"{command}", False)
    return stealthy_ports_commands

def unset_stealthy_ports(stealthy_ports_commands):
    for command in stealthy_ports_commands:
        if args.routing_type == 'iptables':
            if re.search(r"iptables -(A|I)", command):
                delete_iptables_rule(command)
        elif args.routing_type == 'nftables':
            if re.search(r"nft (add|insert) rule", command):
                delete_nftables_rule(command)
        elif args.routing_type == 'vyos':
            if re.search(r"nft (add|insert) rule", command):
                delete_nftables_rule(command)

def init_vars(args, config):
    if args.routing_type == 'nftables':
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

    if args.routing_type == 'vyos':
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
            log(f"NOTE: Since at least one of the configured services has non-local destination, assuming you created chain {nftables_chain_forward} with something like:")
            log(f"          set firewall ipv4 name {nftables_chain_forward} default-action continue")
            log(f"          set firewall ipv4 forward filter rule 20 action jump")
            log(f"          set firewall ipv4 forward filter rule 20 jump-target {nftables_chain_forward}")
            log(f"      And added drop rule for the service port(s)")
            log(f"          set firewall ipv4 name {nftables_chain_forward} rule 100 action drop")
            log(f"          set firewall ipv4 name {nftables_chain_forward} rule 100 protocol _SERVICE_PROTOCOL_")
            log(f"          set firewall ipv4 name {nftables_chain_forward} rule 100 destination port _SERVICE_PORT_")
            log(f"nftables_chain_forward = {args.nftables_chain_forward}")
        log(f"NOTE: Assuming you created chain {nftables_chain_input} with something like:")
        log(f"          set firewall ipv4 name {nftables_chain_input} default-action continue")
        log(f"          set firewall ipv4 input filter rule 20 action jump")
        log(f"          set firewall ipv4 input filter rule 20 jump-target {nftables_chain_input}")
        log(f"      And added drop rule for the service port(s)")
        log(f"          set firewall ipv4 name {nftables_chain_input} rule 100 action drop")
        log(f"          set firewall ipv4 name {nftables_chain_input} rule 100 protocol _SERVICE_PROTOCOL_")
        log(f"          set firewall ipv4 name {nftables_chain_input} rule 100 destination port _SERVICE_PORT_")
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

def parse_args():
    parser = argparse.ArgumentParser(description="Server Application")
    parser.add_argument('-c', '--config', type=str, default='config.yaml', help='Path to the configuration file. If omitted, `config.yaml` in the current directory is used by default')
    parser.add_argument('--http-port', type=int, default=8080, help='Port to run the HTTP server on (default: 8080)')
    parser.add_argument('--https-port', type=int, default=8443, help='Port to run the HTTPS server on (default: 8443)')
    parser.add_argument('--cert', type=str, help='Path to the SSL certificate file. This can be server certificate alone, or a bundle of (1) server, (2) intermediary and (3) root CA certificate, in this order, like TLS expects it.')
    parser.add_argument('--key', type=str, help='Path to the SSL key file')
    parser.add_argument('--routing-type', type=str, default='iptables', choices=['iptables', 'nftables', 'vyos'], help='Type of routing to use (default: iptables)')
    parser.add_argument('--nftables-table-filter', type=str, help='add nftables filter rules to this table (vyos_filter by default when --routing-type vyos)')
    parser.add_argument('--nftables-table-nat', type=str, help='add nftables nat rules to this table (vyos_nat by default when --routing-type vyos)')
    parser.add_argument('--nftables-chain-input', type=str, help='add nftables rules to this table chain, used for local services allow rules')
    parser.add_argument('--nftables-chain-forward', type=str, help='add nftables rules to this table chain, used for non-local services allow rules')
    parser.add_argument('--nftables-chain-default-input', type=str, help='add nftables rules to this table chain hooked to input, used for KnockPort http/https ports')
    parser.add_argument('--nftables-chain-default-output', type=str, help='add nftables rules to this table chain hooked to output, used for KnockPort http/https ports')
    parser.add_argument('--nftables-chain-default-forward', type=str, help='add nftables rules to this table chain hooked to forward, used for KnockPort http/https ports')
    parser.add_argument('--nftables-chain-default-prerouting', type=str, help='add nftables rules to this table chain hooked to nat prerouting, used for non-local services ports')
    parser.add_argument('--nftables-chain-default-postrouting', type=str, help='add nftables rules to this table chain hooked to nat postrouting, used for non-local services ports')
    parser.add_argument('--cleanup', action='store_true', default='False', help='cleanup firewall service(s) rules on shutdown. Do not set this if you want keep access to service(s) in case KnockPort is shut down')
    args = parser.parse_args()
    return args

def shutdown_servers(http_server, https_server, sessions, config, stealthy_ports_commands):
    log("Server is shutting down...")
    http_server.shutdown()
    https_server.shutdown()
    if args.cleanup:
        cleanup_firewall(sessions)
    cleanup_dnat_snat_rules(config)
    unset_stealthy_ports(stealthy_ports_commands)
    sys.exit(0)

def signal_handler(sig, frame, http_server, https_server, sessions, config, stealthy_ports_commands):
    shutdown_servers(http_server, https_server, sessions, config, stealthy_ports_commands)

if __name__ == '__main__':

    args = parse_args()
    app = create_app(args.config, 'session_cache.json')
    init_vars(args, app.config['config'])
    apply_dnat_snat_rules(app.config['config'])

    # Set up iptables/nftables rules for stealthy HTTP/HTTPS server
    stealthy_ports_commands = setup_stealthy_ports(app.config['config'])

    log(f"HTTP Server is starting on 0.0.0.0:{args.http_port}...")
    log(f"HTTPS Server is starting on 0.0.0.0:{args.https_port}...")

    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], stealthy_ports_commands))
    signal.signal(signal.SIGTERM, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], stealthy_ports_commands))

    from threading import Thread

    http_server = make_server('0.0.0.0', args.http_port, app)
    http_server.timeout = 5
    https_server = make_server('0.0.0.0', args.https_port, app, ssl_context=(args.cert, args.key) if args.cert and args.key else None)
    https_server.timeout = 5

    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, http_server, https_server, app.config['sessions'], app.config['config'], stealthy_ports_commands))
    signal.signal(signal.SIGTERM, lambda sig, frame: signal_handler(sig, frame, http_server, https_server, app.config['sessions'], app.config['config'], stealthy_ports_commands))

    http_thread = Thread(target=http_server.serve_forever)
    https_thread = Thread(target=https_server.serve_forever)

    http_thread.start()
    https_thread.start()

    try:
        http_thread.join()
        https_thread.join()
    except KeyboardInterrupt:
        shutdown_servers(http_server, https_server, app.config['sessions'], app.config['config'], stealthy_ports_commands)
