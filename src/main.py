from werkzeug.serving import make_server
import signal
import threading
from app import create_app
from cli import parse_args
from config import init_vars
from firewall import (
    setup_stealthy_ports, cleanup_stealthy_ports,
    apply_nat_rules, cleanup_nat_rules, cleanup_firewall
)
from utils import log
import time

def shutdown_servers(http_server, https_server, app, firewall_commands):
    log("Server is shutting down...")
    http_server.shutdown()
    https_server.shutdown()

    if app.config.get('service_rule_cleanup_on_shutdown', True):
        log("> Removing service sessions firewall rules")
        cleanup_firewall(app.config['sessions'], app.args.firewall_type)
        log("> Removing dnat/snat firewall rules")
        cleanup_nat_rules(app.config['config'], app.args)
    else:
        log("> Not removing service sessions and dnat/snat firewall rules, service access is still enabled")

    log("> Removing stealthy ports firewall rules")
    cleanup_stealthy_ports(firewall_commands, app.args)

def signal_handler(sig, frame, http_server, https_server, app, firewall_commands):
    stop_event = app.config.get('stop_event')
    if stop_event:
        stop_event.set()
        time.sleep(1)
    shutdown_servers(http_server, https_server, app, firewall_commands)

if __name__ == '__main__':
    args = parse_args()
    app = create_app(args.config, 'cache/sessions.json', args)
    app.args = args  # Store args in app config for access in shutdown

    init_vars(args, app.config['config'])
    apply_nat_rules(app.config['config'], args)

    # Set up firewall rules for stealthy HTTP/HTTPS server
    firewall_commands = setup_stealthy_ports(app.config['config'], args, app)

    log(f"HTTP Server is starting on 0.0.0.0:{args.http_port}...")
    log(f"HTTPS Server is starting on 0.0.0.0:{args.https_port}...")

    http_server = make_server('0.0.0.0', args.http_port, app)
    http_server.timeout = 5
    https_server = make_server('0.0.0.0', args.https_port, app, ssl_context=(args.cert, args.key) if args.cert and args.key else None)
    https_server.timeout = 5

    # Set up signal handlers
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, http_server, https_server, app, firewall_commands))
    signal.signal(signal.SIGTERM, lambda sig, frame: signal_handler(sig, frame, http_server, https_server, app, firewall_commands))

    # Start servers in threads
    http_thread = threading.Thread(target=http_server.serve_forever)
    https_thread = threading.Thread(target=https_server.serve_forever)

    http_thread.start()
    https_thread.start()

    try:
        http_thread.join()
        https_thread.join()
    except KeyboardInterrupt:
        shutdown_servers(http_server, https_server, app, firewall_commands)
