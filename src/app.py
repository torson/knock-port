import json
import time
from flask import Flask, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Length
import warnings
from threading import Thread, Lock
from utils import log, log_err
from sessions import manage_sessions, monitor_stealthy_ports
from firewall import add_iptables_rule, add_nftables_rule

# Suppress specific warnings
warnings.filterwarnings("ignore", category=UserWarning, module='flask_limiter.extension')

app = Flask(__name__)
app.config['WTF_CSRF_ENABLED'] = False

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
limiter.init_app(app)

class RequestForm(FlaskForm):
    app = StringField('app', validators=[DataRequired(), Length(min=1, max=50)])
    access_key = StringField('access_key', validators=[DataRequired(), Length(min=10, max=50)])

def handle_request(config, sessions, lock, session_file, access_key_type, args):
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
        interface_ext = config[app_name].get('interface_ext', config['global']['interface_ext'])
        interface_int = config[app_name].get('interface_int', config['global']['interface_int'])
        port_to_open = config[app_name]['port']
        if access_key_type == "http":
            if config[app_name]['step2_https_duration']:
                duration = config[app_name]['step2_https_duration']
            else:
                duration = 60
            protocol = "tcp"
            port_to_open = args.https_port
            log(f"Opening https port {port_to_open} for {client_ip} on {interface_ext} for 5s")
        else:
            duration = config[app_name]['duration']
            protocol = config[app_name]['protocol']
            log(f"Opening service {app_name} {protocol} port {port_to_open} for {client_ip} on {interface_ext} for {duration}s")
        
        if args.firewall_type == 'iptables':
            if config[app_name]['destination'] == "local":
                command = f"iptables -I INPUT -i {interface_ext} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
            else:
                if access_key_type == "http":
                    command = f"iptables -I INPUT -i {interface_ext} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
                else:
                    command = f"iptables -I FORWARD -o {interface_int} -p {protocol} -s {client_ip} --dport {port_to_open} -j ACCEPT -m comment --comment 'ipv4-FWD-KnockPort-{interface_int}-{app_name}-{protocol}-{port_to_open}-{client_ip}'"
            add_iptables_rule(command)
        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
            if config[app_name]['destination'] == "local":
                command = f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface_ext} counter accept comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'"
            else:
                if access_key_type == "http":
                    command = f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} iifname {interface_ext} counter accept comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'"
                else:
                    command = f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_forward} index 0 {protocol} dport {port_to_open} ip saddr {client_ip} oifname {interface_int} counter accept comment 'ipv4-FWD-KnockPort-{interface_int}-{app_name}-{protocol}-{port_to_open}-{client_ip}-accept'"
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

def create_app(config_path, session_file, args):
    config = load_config(config_path)
    app.config['config'] = config
    sessions = []
    lock = Lock()

    try:
        with open(session_file, 'r') as f:
            sessions = json.load(f)
    except FileNotFoundError:
        log("No existing session file found. Starting fresh.")

    session_manager = Thread(target=manage_sessions, args=(session_file, sessions, lock, args.firewall_type))
    session_manager.daemon = True
    session_manager.start()

    stop_event = threading.Event()
    stealthy_ports_monitor = Thread(target=monitor_stealthy_ports, args=(config, stop_event, session_file, args))
    app.config['stop_event'] = stop_event
    stealthy_ports_monitor.daemon = True
    stealthy_ports_monitor.start()

    @app.route(config['global']['http_post_path'], methods=['POST'])
    @limiter.limit(f"{config['global']['step1_2_rate_limit_per_minute']} per minute")
    def handle_http_request():
        log(f"Received HTTP {request.method} request from {request.remote_addr}")
        if request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'http', args)

    @app.route(config['global']['https_post_path'], methods=['POST'])
    @limiter.limit(f"{config['global']['step1_2_rate_limit_per_minute']} per minute")
    def handle_https_request():
        log(f"Received HTTPS {request.method} request from {request.remote_addr}")
        if request.method == 'POST':
            return handle_request(config, sessions, lock, session_file, 'https', args)

    @app.errorhandler(500)
    def handle_500(error):
        log("Server Error 500")
        abort(503)

    app.config['sessions'] = sessions
    return app
