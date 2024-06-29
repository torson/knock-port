
import argparse
import yaml
import time
import sys
from flask import Flask, request, abort
from threading import Thread, Lock
import json
import subprocess
from subprocess import Popen, PIPE
import re
import os
from pprint import pprint
import pprint
from sh import bash

app = Flask(__name__)

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

def manage_sessions(session_file, sessions, lock, test_mode):
    while True:
        current_time = time.time()
        with lock:
            if sessions is None:
                sessions = []
            expired_sessions = [s for s in sessions if current_time > s['expires_at']]
            for session in expired_sessions:
                sessions.remove(session)
                with open(session_file, 'w') as f:
                    json.dump(sessions, f)
                if args.routing_type == 'iptables':
                    command = session['command'].replace('-I', '-D')
                    if test_mode:
                        log(f"Mock command: {command}")
                    else:
                        log(f"Executing command: {command}")
                        try:
                            log(str(bash('-c', command)))
                        except Exception as e:
                            log_err("Error during operations:", e)
                elif args.routing_type == 'nftables':
                    delete_nftables_rule(session['command'], test_mode)
                elif args.routing_type == 'vyos':
                    delete_nftables_rule(session['command'], test_mode)
        time.sleep(5)

def create_app(config_path, session_file, test_mode):
    config = load_config(config_path)
    sessions = []
    lock = Lock()
    if test_mode:
        log("Running in test mode. Commands will be mocked.")

    try:
        with open(session_file, 'r') as f:
            sessions = json.load(f)
    except FileNotFoundError:
        log_err("No existing session file found. Starting fresh.")

    session_manager = Thread(target=manage_sessions, args=(session_file, sessions, lock, test_mode))
    session_manager.daemon = True
    session_manager.start()

    @app.route('/', methods=['GET', 'POST'])
    def handle_http_request():
        log(f"Received HTTP {request.method} request from {request.remote_addr}")
        if request.method == 'GET':
            log("Aborting GET request with 404")
            abort(404)
        elif request.method == 'POST':
            log("Processing HTTP POST request")
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            log(f"Client IP: {client_ip}")
            # Open HTTPS port for the client IP for 10 seconds
            https_port = config['https_port']
            duration = 10
            if args.routing_type == 'iptables':
                command = f"iptables -I INPUT -p tcp -s {client_ip} --dport {https_port} -j ACCEPT"
            elif args.routing_type == 'nftables':
                command = f"nft insert rule ip {args.nftables_table} {args.nftables_chain} index 0 tcp dport {https_port} ip saddr {client_ip} counter accept comment 'ipv4-IN-KnockPort-tmp-HTTPS-{https_port}-{client_ip}'"
            try:
                if test_mode:
                    log(f"Mock command: {command}")
                else:
                    log(f"Executing command: {command}")
                    log(str(bash('-c', command, _tty_out=True)))
                with lock:
                    sessions.append({'command': command, 'expires_at': time.time() + duration})
                    with open(session_file, 'w') as f:
                        json.dump(sessions, f)
            except Exception as e:
                log_err(f"Error during operations: {e}")
        abort(503)

    @app.route('/secure', methods=['POST'])
    def handle_https_request():
        log(f"Received HTTPS POST request from {request.remote_addr}")
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
        if app_name in config and config[app_name]['access_key'] == access_key:
            port = config[app_name]['port']
            destination = config[app_name]['destination']
            duration = config[app_name]['duration']
            protocol = config[app_name]['protocol']
            interface = config[app_name]['interface']
            if destination == "local":
                if args.routing_type == 'iptables':
                    command = f"iptables -I INPUT -p {protocol} -s {client_ip} --dport {port} -j ACCEPT"
                elif args.routing_type == 'nftables':
                    command = f"nft insert rule ip {args.nftables_table} {args.nftables_chain} index 0 {protocol} dport {port} ip saddr {client_ip} iifname {interface} counter accept comment 'ipv4-IN-KnockPort-tmp-{interface}-{protocol}-{port}-{client_ip}'"
                elif args.routing_type == 'vyos':
                    command = f"nft insert rule ip {args.nftables_table} {args.nftables_chain} index 0 {protocol} dport {port} ip saddr {client_ip} iifname {interface} counter accept comment 'ipv4-IN-KnockPort-tmp-{interface}-{protocol}-{port}-{client_ip}'"
            else:
                if args.routing_type == 'iptables':
                    command = f"iptables -I FORWARD -p {protocol} -s {client_ip} -d {destination} --dport {port} -j ACCEPT"
            session_exists = False
            expires_at = time.time() + duration
            for session in sessions:
                if session['command'] == command:
                    log("Session is duplicate, updating 'expires_at'")
                    session['expires_at'] = expires_at
                    session_exists = True
                    break
            if not session_exists:
                try:
                    if test_mode:
                        log(f"Mock command: {command}")
                    else:
                        log(f"Executing command: {command}")
                        log(str(bash('-c', command, _tty_out=True)))
                    with lock:
                        sessions.append({'command': command, 'expires_at': expires_at})
                        with open(session_file, 'w') as f:
                            json.dump(sessions, f)
                except Exception as e:
                    log_err(f"Error during operations: {e}")
        else:
            log_err(f"Unauthorized access attempt or invalid app credentials for App: {app_name}, Access Key: {access_key}")
        abort(503)
    app.config['config'] = config
    app.config['sessions'] = sessions
    return app

def delete_nftables_rule(command, test_mode):
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
        if test_mode:
            log(f"Mock command: {command_nft_list} ... parsing")
            log(f"Mock command: {command_nft_delete} HANDLE_NUM")
        else:
            try:
                command = f"{command_nft_list} | grep {comment} | grep 'handle'" + " | awk '{print $NF}'"
                log(f"Executing command: {command}")
                handle = bash('-c', command, _tty_out=True)
                handle = handle.strip()
                if handle:
                    log(f"Executing command: {command_nft_delete} {handle}")
                    output = bash('-c', f"{command_nft_delete} {handle}")
                    log(f"Delete operation successful: {output}")
                else:
                    log_err("No valid handle found.")
            except Exception as e:
                log_err(f"Error during operations: {e}")
    else:
        log_err(f"nftables : No match found with '{command_nft_list}' for : {command}")

def cleanup_iptables(sessions, test_mode):
    for session in sessions:
        if args.routing_type == 'iptables':
            command = session['command'].replace('-A', '-D')
            if test_mode:
                subprocess.run(["echo", "Mock command: ", *command.split()], check=True)
            else:
                log(f"Executing command: {command}")
                subprocess.run(command.split(), check=True)
        elif args.routing_type == 'nftables':
            delete_nftables_rule(session['command'], test_mode)

def apply_dnat_snat_rules(config, test_mode):
    for app_name, app_config in config.items():
        if app_config['destination'] != "local":
            dnat_command = f"iptables -t nat -A PREROUTING -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']}"
            snat_command = f"iptables -t nat -A POSTROUTING -o {app_config['interface']} -p {app_config['protocol']} -s {app_config['destination']} --sport {app_config['port']} -j MASQUERADE"
            if test_mode:
                subprocess.run(["echo", "Mock command: ", *dnat_command.split()], check=True)
                subprocess.run(["echo", "Mock command: ", *snat_command.split()], check=True)
            else:
                log(f"Executing command: {dnat_command}")
                subprocess.run(dnat_command.split(), check=True)
                log(f"Executing command: {snat_command}")
                subprocess.run(snat_command.split(), check=True)

def cleanup_dnat_snat_rules(config, test_mode):
    for app_name, app_config in config.items():
        if app_config['destination'] != "local":
            dnat_command = f"iptables -t nat -D PREROUTING -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']}"
            snat_command = f"iptables -t nat -D POSTROUTING -o {app_config['interface']} -p {app_config['protocol']} -s {app_config['destination']} --sport {app_config['port']} -j MASQUERADE"
            if test_mode:
                subprocess.run(["echo", "Mock command: ", *dnat_command.split()], check=True)
                subprocess.run(["echo", "Mock command: ", *snat_command.split()], check=True)
            else:
                log(f"Executing command: {dnat_command}")
                subprocess.run(dnat_command.split(), check=True)
                log(f"Executing command: {snat_command}")
                subprocess.run(snat_command.split(), check=True)

def signal_handler(sig, frame, sessions, config, test_mode):
    log("Server is shutting down...")
    cleanup_iptables(sessions, test_mode)
    cleanup_dnat_snat_rules(config, test_mode)
    sys.exit(0)

if __name__ == '__main__':
    import sys
    import signal
    parser = argparse.ArgumentParser(description="Server Application")
    parser.add_argument('-c', '--config', type=str, default='config.yaml', help='Path to the configuration file. If omitted, `config.yaml` in the current directory is used by default')
    parser.add_argument('-t', '--test', action='store_true', help='Enable test mode to mock iptables commands')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to run the server on (default: 8080)')
    parser.add_argument('--cert', type=str, help='Path to the SSL certificate file. This can be server certificate alone, or a bundle of (1) server, (2) intermediary and (3) root CA certificate, in this order, like TLS expects it.')
    parser.add_argument('--key', type=str, help='Path to the SSL key file')
    parser.add_argument('--routing-type', type=str, default='iptables', choices=['iptables', 'nftables', 'vyos'], help='Type of routing to use (default: iptables)')
    parser.add_argument('--nftables-table', type=str, help='add nftables rules to this table (vyos_filter by default when --routing-type vyos)')
    parser.add_argument('--nftables-chain', type=str, help='add nftables rules to this table chain')
    parser.add_argument('--rule-description', type=str, default='', help='Description to add to the firewall rule')
    args = parser.parse_args()

    if args.routing_type == 'vyos':
        if not args.nftables_table :
            # table vyos_filter is used by VyOs so we set it as default
            args.nftables_table = "vyos_filter"
        if not args.nftables_chain :
            args.nftables_chain = "VYOS_INPUT_filter"

    if args.routing_type == 'nftables':
        if not args.nftables_table :
            # table vyos_filter is used by VyOs so we set it as default
            args.nftables_table = "filter"
        if not args.nftables_chain :
            # table vyos_filter is used by VyOs so we set it as default
            args.nftables_chain = "INPUT"

    app = create_app(args.config, 'session_cache.json', args.test)
    apply_dnat_snat_rules(app.config['config'], args.test)
    log(f"Server is starting on 0.0.0.0:{args.port}...")
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], args.test))
    signal.signal(signal.SIGTERM, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], args.test))
    if args.cert and args.key:
        app.run(host='0.0.0.0', port=args.port, ssl_context=(args.cert, args.key))
    else:
        app.run(host='0.0.0.0', port=args.port)
