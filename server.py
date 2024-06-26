
import argparse
import yaml
import time
from flask import Flask, request, abort
from threading import Thread, Lock
import json
import subprocess

app = Flask(__name__)

def load_config(config_path):
    print("Loading configuration...")
    with open(config_path, 'r') as config_file:
        return yaml.safe_load(config_file)

def manage_sessions(session_file, sessions, lock, test_mode):
    while True:
        time.sleep(5)
        current_time = time.time()
        with lock:
            if sessions is None:
                sessions = []
            expired_sessions = [s for s in sessions if current_time > s['expires_at']]
            for session in expired_sessions:
                sessions.remove(session)
                iptables_command = session['iptables_command'].replace('-A', '-D')
                if test_mode:
                    subprocess.run(["echo", "Mock command: ", *iptables_command.split()], check=True)
                else:
                    print(f"Executing command: {iptables_command}")
                    subprocess.run(iptables_command.split(), check=True)
            with open(session_file, 'w') as f:
                json.dump(sessions, f)

def create_app(config_path, session_file, test_mode):
    config = load_config(config_path)
    sessions = []
    lock = Lock()
    if test_mode:
        print("Running in test mode. Commands will be mocked.")

    try:
        with open(session_file, 'r') as f:
            sessions = json.load(f)
    except FileNotFoundError:
        print("No existing session file found. Starting fresh.")

    session_manager = Thread(target=manage_sessions, args=(session_file, sessions, lock, test_mode))
    session_manager.daemon = True
    session_manager.start()

    @app.route('/', methods=['POST'])
    def handle_request():  # This function is used by Flask to handle POST requests
        print("Received POST request")
        data = request.form
        try:
            app_name = data['app']
            access_key = data['access_key']
        except ValueError:
            print("Invalid data format received")
            abort(503)
        print(f"Parsed form data - App: {app_name}, Access Key: {access_key}")

        client_ip = request.remote_addr
        if app_name in config and config[app_name]['access_key'] == access_key:
            port = config[app_name]['port']
            destination = config[app_name]['destination']
            duration = config[app_name]['duration']
            protocol = config[app_name]['protocol']
            if destination == "local":
                iptables_command = f"iptables -A INPUT -p {protocol} -s {client_ip} --dport {port} -j ACCEPT"
            else:
                iptables_command = f"iptables -A FORWARD -p {protocol} -s {client_ip} -d {destination} --dport {port} -j ACCEPT"
            session_exists = False
            expires_at = time.time() + duration
            for session in sessions:
                if session['iptables_command'] == iptables_command:
                    session['expires_at'] = expires_at
                    session_exists = True
                    print("Session is duplicate, updating 'expires_at'")
                    break
            if not session_exists:
                if test_mode:
                    subprocess.run(["echo", "Mock command: ", *iptables_command.split()], check=True)
                else:
                    print(f"Executing command: {iptables_command}")
                    subprocess.run(iptables_command.split(), check=True)
                with lock:
                    sessions.append({'iptables_command': iptables_command, 'expires_at': expires_at})
        else:
            print(f"Unauthorized access attempt or invalid app credentials for App: {app_name}, Access Key: {access_key}")
        abort(503)
    return app

def cleanup_iptables(sessions, test_mode):
    for session in sessions:
        iptables_command = session['iptables_command'].replace('-A', '-D')
        if test_mode:
            subprocess.run(["echo", "Mock command: ", *iptables_command.split()], check=True)
        else:
            print(f"Executing command: {iptables_command}")
            subprocess.run(iptables_command.split(), check=True)

def apply_dnat_snat_rules(config, test_mode):
    for app_name, app_config in config.items():
        if app_config['destination'] != "local":
            dnat_command = f"iptables -t nat -A PREROUTING -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']}"
            snat_command = f"iptables -t nat -A POSTROUTING -p {app_config['protocol']} --dport {app_config['port']} -j MASQUERADE"
            if test_mode:
                subprocess.run(["echo", "Mock command: ", *dnat_command.split()], check=True)
                subprocess.run(["echo", "Mock command: ", *snat_command.split()], check=True)
            else:
                print(f"Executing command: {dnat_command}")
                subprocess.run(dnat_command.split(), check=True)
                print(f"Executing command: {snat_command}")
                subprocess.run(snat_command.split(), check=True)

def cleanup_dnat_snat_rules(config, test_mode):
    for app_name, app_config in config.items():
        if app_config['destination'] != "local":
            dnat_command = f"iptables -t nat -D PREROUTING -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']}"
            snat_command = f"iptables -t nat -D POSTROUTING -p {app_config['protocol']} --dport {app_config['port']} -j MASQUERADE"
            if test_mode:
                subprocess.run(["echo", "Mock command: ", *dnat_command.split()], check=True)
                subprocess.run(["echo", "Mock command: ", *snat_command.split()], check=True)
            else:
                print(f"Executing command: {dnat_command}")
                subprocess.run(dnat_command.split(), check=True)
                print(f"Executing command: {snat_command}")
                subprocess.run(snat_command.split(), check=True)

def signal_handler(sig, frame, sessions, config, test_mode):
    print("Server is shutting down...")
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
    args = parser.parse_args()

    app = create_app(args.config, 'session_cache.json', args.test)
    apply_dnat_snat_rules(app.config['config'], args.test)
    print(f"Server is starting on port {args.port}...")
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], args.test))
    signal.signal(signal.SIGTERM, lambda sig, frame: signal_handler(sig, frame, app.config['sessions'], app.config['config'], args.test))
    app.run(port=args.port)
