
import argparse
import yaml
import time
from flask import Flask, request, abort
from threading import Thread, Lock
import json

app = Flask(__name__)

def load_config(config_path):
    with open(config_path, 'r') as config_file:
        return yaml.safe_load(config_file)

def manage_sessions(session_file, sessions, lock, test_mode):
    while True:
        time.sleep(5)
        current_time = time.time()
        with lock:
            expired_sessions = [s for s in sessions if current_time > s['expires_at']]
            for session in expired_sessions:
                sessions.remove(session)
                if test_mode:
                    print(f"echo iptables -D {session['iptables_command']}")
                else:
                    print(f"iptables -D {session['iptables_command']}")
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
    def handle_request():
        data = request.data.decode()
        app_name, access_key = data.split('=')
        client_ip = request.remote_addr
        if app_name in config and config[app_name]['access_key'] == access_key:
            port = config[app_name]['port']
            destination = config[app_name]['destination']
            duration = config[app_name]['duration']
            expires_at = time.time() + duration
            if destination == "local":
                iptables_command = f"iptables -A INPUT -s {client_ip} -p tcp --dport {port} -j ACCEPT"
            else:
                ip, port = destination.split(':')
                iptables_command = f"iptables -A FORWARD -s {client_ip} -d {ip} --dport {port} -j ACCEPT"
            if test_mode:
                iptables_command = "echo " + iptables_command
            print(iptables_command)
            with lock:
                sessions.append({'iptables_command': iptables_command, 'expires_at': expires_at})
        abort(503)
    return app

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Server Application")
    parser.add_argument('-c', '--config', type=str, default='config.yaml', help='Path to configuration file')
    parser.add_argument('-t', '--test', action='store_true', help='Enable test mode to mock iptables commands')
    args = parser.parse_args()
    
    app = create_app(args.config, 'session_cache.json', args.test)
    app.run(port=8080)
