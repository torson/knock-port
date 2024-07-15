
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

from gevent import monkey
monkey.patch_all()

app = Flask(__name__)
app.config['WSGI_READ_TIMEOUT'] = 5

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

def execute_command(command, print_command=True):
    if print_command:
        log(f"Executing command: {command}")
    out=str(bash('-c', command, _tty_out=True)).strip()
    if out:
        log(out)

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

def handle_request(config, sessions, lock, session_file, access_key_type):
    log(f"Received request from {request.remote_addr}")
    data = request.form
    log(f"Received data: {dict(data)}")
    try:
        app_name = data['app']
        access_key = data['access_key']
    except KeyError as e:
        log_err(f"KeyError: {e}")
        log_err("Invalid data format received")
        abort(503)
    log(f"Parsed form data - App: {app_name}, Access Key: {access_key}")
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    log(f"Client IP: {client_ip}")
    if app_name in config and access_key in config[app_name][f'access_key_{access_key_type}']:
        interface = config[app_name]['interface']
        port_to_open = config[app_name]['port']
        if access_key_type == "http":
            log(f"Opening http port {port_to_open} for {client_ip} on {interface} for 5s")
            duration = config[app_name]['phase2_https_duration']
            protocol = "tcp"
            port_to_open = args.https_port
        else:
            duration = config[app_name]['duration']
            protocol = config[app_name]['protocol']
            log(f"Opening {app_name} {protocol} port {port_to_open} for {client_ip} on {interface} for {duration}s")
        if args.routing_type == 'iptables':
            command = f"iptables -I INPUT -i {interface} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
            add_iptables_rule(command)
        elif args.routing_type == 'nftables':
            command = f"nft insert rule ip {args.nftables_table} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface} counter accept comment 'ipv4-IN-KnockPort-{interface}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
            add_nftables_rule(command)
        elif args.routing_type == 'vyos':
            command = f"nft insert rule ip {args.nftables_table} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface} counter accept comment 'ipv4-IN-KnockPort-{interface}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
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

    @app.route('/phase-1', methods=['GET', 'POST'])
    def handle_http_request():
        log(f"Received HTTP {request.method} request from {request.remote_addr}")
        if request.method == 'GET':
            log("Aborting GET request with 404")
            abort(404)
        elif request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'http')

    @app.route('/phase-2', methods=['POST'])
    def handle_https_request():
        log(f"Received HTTPS {request.method} request from {request.remote_addr}")
        if request.method == 'GET':
            log("Aborting GET request with 404")
            abort(404)
        elif request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'https')

    app.config['config'] = config
    app.config['sessions'] = sessions
    return app

## iptables
def iptables_rule_exists(command, output=False):
    pattern = r'^\S+\s+\S+\s+(\S+)\s+.*comment\s\'([^\']+)\''
    match = re.search(pattern, command)
    if match:
        table = match.group(1)
        comment = match.group(2)
        command_rules_list = f"iptables -n -v -L {table}"
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
    for app_name, app_config in config.items():
        if app_config['destination'] != "local":
            dnat_command = f"iptables -t nat -A PREROUTING -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']}"
            snat_command = f"iptables -t nat -A POSTROUTING -o {app_config['interface']} -p {app_config['protocol']} -s {app_config['destination']} --sport {app_config['port']} -j MASQUERADE"
            log(f"Executing command: {dnat_command}")
            subprocess.run(dnat_command.split(), check=True)
            log(f"Executing command: {snat_command}")
            subprocess.run(snat_command.split(), check=True)

def cleanup_dnat_snat_rules(config):
    for app_name, app_config in config.items():
        if app_config['destination'] != "local":
            dnat_command = f"iptables -t nat -D PREROUTING -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']}"
            snat_command = f"iptables -t nat -D POSTROUTING -o {app_config['interface']} -p {app_config['protocol']} -s {app_config['destination']} --sport {app_config['port']} -j MASQUERADE"
            log(f"Executing command: {dnat_command}")
            subprocess.run(dnat_command.split(), check=True)
            log(f"Executing command: {snat_command}")
            subprocess.run(snat_command.split(), check=True)

def setup_stealthy_ports():
    if args.routing_type == 'iptables':
        stealthy_ports_commands = [
            "echo Allow incoming packets to HTTP port",
                f"iptables -A INPUT -p tcp --dport {args.http_port} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-tcp-dport-{args.http_port}-accept'",
            "echo Drop outgoing traffic from KnockPort HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a response from HTTP port",
                f"iptables -A OUTPUT -p tcp --sport {args.http_port} --tcp-flags ALL SYN,ACK -j ACCEPT -m comment --comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-syn-ack-accept'",
                f"iptables -A OUTPUT -p tcp --sport {args.http_port} -j DROP -m comment --comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-drop'",
            "echo Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP port",
                f"iptables -A INPUT -p tcp --dport {args.https_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'"
        ]
        for command in stealthy_ports_commands:
            if re.search(r"iptables -(A|I)", command):
                add_iptables_rule(command)
            else:
                execute_command(f"{command}", False)
    elif args.routing_type == 'nftables':
        stealthy_ports_commands = [
            "echo Allow incoming packets to HTTP port",
                f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_input} index 0 tcp dport {args.http_port} counter accept comment 'ipv4-IN-KnockPort-tcp-dport-{args.http_port}-accept'",
            "echo Drop outgoing traffic from KnockPort HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a response from HTTP port",
                f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} tcp sport {args.http_port} counter drop comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-drop'",
                f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} 'tcp flags & (syn|ack) == syn|ack' counter accept comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-syn-ack-accept'",
            "echo Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP port",
                f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_input} index 0 tcp dport {args.https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'"
        ]
        for command in stealthy_ports_commands:
            if re.search(r"nft (add|insert) rule", command):
                add_nftables_rule(command)
            else:
                execute_command(f"{command}", False)
    elif args.routing_type == 'vyos':
        # with VyOS we're handling the jump to the separate args.nftables_chain_input
        # stealthy_ports_commands = [
        #     "echo Allow incoming packets to HTTP port",
        #         f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_input} index 0 tcp dport {args.http_port} counter accept comment 'ipv4-IN-KnockPort-tcp-dport-{args.http_port}-accept'",
        #     "echo Drop outgoing traffic from KnockPort HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a response from HTTP port",
        #         f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} counter drop comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-drop'",
        #         f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} 'tcp flags & (syn|ack) == syn|ack' counter accept comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-syn-ack-accept'",
        #     "echo Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP port",
        #         f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_input} index 0 tcp dport {args.https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'"
        # ]

        stealthy_ports_commands = [
            "echo Allow incoming packets to HTTP port",
                f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_input} index 0 tcp dport {args.http_port} counter accept comment 'ipv4-IN-KnockPort-tcp-dport-{args.http_port}-accept'",
            "echo Drop outgoing traffic from KnockPort HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a response from HTTP port",
                f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} counter drop comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-drop'",
                f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} 'tcp flags & (syn|ack) == syn|ack' counter accept comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-syn-ack-accept'",
            "echo Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP port",
        ]

        # log("Allow incoming packets to HTTP port")
        # add_nftables_rule(f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_input} index 0 tcp dport {args.http_port} counter accept comment 'ipv4-IN-KnockPort-tcp-dport-{args.http_port}-accept'")

        # log("Drop outgoing traffic from KnockPort HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a response from HTTP port")
        # add_nftables_rule(f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} counter drop comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-drop'")
        # add_nftables_rule(f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_output} index 0 tcp sport {args.http_port} 'tcp flags & (syn|ack) == syn|ack' counter accept comment 'ipv4-OUT-KnockPort-tcp-sport-{args.http_port}-syn-ack-accept'")

        # log("Drop incoming packets to HTTPS port. Per IP allow rules will be created on request to HTTP/HTTPS port")

        jump_command = f"nft add rule ip {args.nftables_table} {args.nftables_chain_default_input} counter jump {args.nftables_chain_input} comment 'ipv4-INP-filter-20'"
        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+jump\s+(\S+)\s+comment\s.+'
        jump_command_handle = nftables_rule_exists(jump_command, False, pattern)
        if jump_command_handle:
            # add_nftables_rule(f"nft add rule ip {args.nftables_table} {args.nftables_chain_default_input} index {jump_command_handle} tcp dport {args.https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'")
            stealthy_ports_commands.append(f"nft add rule ip {args.nftables_table} {args.nftables_chain_default_input} handle {jump_command_handle} tcp dport {args.https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'")
        else:
            stealthy_ports_commands.append(f"nft insert rule ip {args.nftables_table} {args.nftables_chain_default_input} index 0 tcp dport {args.https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{args.https_port}-drop'")
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

def init_vars(args):
    if args.routing_type == 'nftables':
        if not args.nftables_table:
            # table filter is used on Debian so we set it as default
            args.nftables_table = "filter"
        log(f"nftables_table = {args.nftables_table}")
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

    if args.routing_type == 'vyos':
        if not args.nftables_table:
            # table vyos_filter is used on VyOs so we set it as default
            args.nftables_table = "vyos_filter"
        log(f"nftables_table = {args.nftables_table}")
        if not args.nftables_chain_input:
            # chain used for KnockPort service allow rules
            # if you add a chain IN-KnockPort with 'set firewall ipv4 name IN-KnockPort' then that is set into table vyos_filter (check with 'nft list ruleset')
            # and the actual name of the chain becomes NAME_IN-KnockPort
            args.nftables_chain_input = "NAME_IN-KnockPort"
        nftables_chain_input = args.nftables_chain_input[len("NAME_"):]
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

def parse_args():
    parser = argparse.ArgumentParser(description="Server Application")
    parser.add_argument('-c', '--config', type=str, default='config.yaml', help='Path to the configuration file. If omitted, `config.yaml` in the current directory is used by default')
    parser.add_argument('--http-port', type=int, default=8080, help='Port to run the HTTP server on (default: 8080)')
    parser.add_argument('--https-port', type=int, default=8443, help='Port to run the HTTPS server on (default: 8443)')
    parser.add_argument('--cert', type=str, help='Path to the SSL certificate file. This can be server certificate alone, or a bundle of (1) server, (2) intermediary and (3) root CA certificate, in this order, like TLS expects it.')
    parser.add_argument('--key', type=str, help='Path to the SSL key file')
    parser.add_argument('--routing-type', type=str, default='iptables', choices=['iptables', 'nftables', 'vyos'], help='Type of routing to use (default: iptables)')
    parser.add_argument('--nftables-table', type=str, help='add nftables rules to this table (vyos_filter by default when --routing-type vyos)')
    parser.add_argument('--nftables-chain-input', type=str, help='add nftables rules to this table chain, used for service allow rules')
    parser.add_argument('--nftables-chain-default-input', type=str, help='add nftables rules to this table chain hooked to input, used for KnockPort http/https ports')
    parser.add_argument('--nftables-chain-default-output', type=str, help='add nftables rules to this table chain hooked to output, used for KnockPort http/https ports')
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
    init_vars(args)
    app = create_app(args.config, 'session_cache.json')
    apply_dnat_snat_rules(app.config['config'])

    # Set up iptables/nftables rules for stealthy HTTP/HTTPS server
    stealthy_ports_commands = setup_stealthy_ports()

    log(f"HTTP Server is starting on 0.0.0.0:{args.http_port}...")
    log(f"HTTPS Server is starting on 0.0.0.0:{args.https_port}...")
    
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], stealthy_ports_commands))
    signal.signal(signal.SIGTERM, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], stealthy_ports_commands))
    
    from threading import Thread
    
    http_server = make_server('0.0.0.0', args.http_port, app)
    https_server = make_server('0.0.0.0', args.https_port, app, ssl_context=(args.cert, args.key) if args.cert and args.key else None)
    
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
