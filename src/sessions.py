import time
import json
import os
from utils import log, execute_command_with_pipes
from firewall import (
    add_iptables_rule, delete_iptables_rule,
    add_nftables_rule, delete_nftables_rule,
    setup_stealthy_ports, apply_nat_rules
)

def manage_sessions(session_file, sessions, lock, firewall_type, args):
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
                if firewall_type == 'iptables':
                    delete_iptables_rule(command, use_sudo=args.use_sudo)
                elif firewall_type == 'nftables' or firewall_type == 'vyos':
                    delete_nftables_rule(session['command'], use_sudo=args.use_sudo)
        time.sleep(1)

def monitor_stealthy_ports(config, stop_event, session_file, args, app):
    # in case there's unintended rules change that KnockPort relies on we reapply stealthy ports rules
    time.sleep(30)
    while True:
        http_port = args.waf_http_port if args.waf_http_port else args.http_port
        if stop_event.is_set():
            break
        elif args.firewall_type == 'iptables':
            command1 = "iptables -n -v -L"
            command2 = f"grep ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-drop"
        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
            # on VyOs if you make a firewall change it will reset all chains to what is set up with set "set" commands
            # we're just checking for this one rule since it's most important
            command1 = f"nft -a list chain ip {args.nftables_table_filter} {args.nftables_chain_default_input}"
            command2 = f"grep ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-drop"

        try:
            out = execute_command_with_pipes(command=command1, command2=command2, print_command=False, print_output=False, use_sudo=args.use_sudo)
        except Exception:
            # If grep doesn't find anything, it will return non-zero exit code, which is expected
            # This is equivalent to the "; true" that was in the original command
            out = ""
        if not out:
            log("!!! Stealthy port rule for HTTP drop missing")
            log(" > re-applying all stealthy HTTP/HTTPS port rules")
            setup_stealthy_ports(config, args, app)
            log(" > re-applying all nat rules")
            apply_nat_rules(config, args)
            try:
                with open(session_file, 'r') as f:
                    sessions = json.load(f)
                    log(" > re-applying all services access rules")
                    for session in sessions:
                        command = session['command']
                        if args.firewall_type == 'iptables':
                            add_iptables_rule(command, use_sudo=args.use_sudo)
                        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
                            add_nftables_rule(command, use_sudo=args.use_sudo)
            except FileNotFoundError:
                log("No existing session file found. Skipping session rules reapplication.")
        time.sleep(5)
