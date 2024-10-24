import time
import json
import os
from threading import Thread
from utils import log
from firewall import add_iptables_rule, delete_iptables_rule, add_nftables_rule, delete_nftables_rule

def manage_sessions(session_file, sessions, lock, firewall_type):
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
                    delete_iptables_rule(command)
                elif firewall_type == 'nftables' or firewall_type == 'vyos':
                    delete_nftables_rule(session['command'])
        time.sleep(1)

def monitor_stealthy_ports(config, stop_event, session_file, args):
    # in case there's unintended rules change that Knock-Port relies on we reapply stealthy ports rules
    time.sleep(30)
    while True:
        if stop_event.is_set():
            break
        elif args.firewall_type == 'iptables':
            command = f"iptables -n -v -L | grep ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{args.http_port}-drop ; true"
        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
            command = f"nft -a list chain ip {args.nftables_table_filter} {args.nftables_chain_default_input} | grep ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{args.http_port}-drop ; true"
        out = execute_command(command, print_command=False, print_output=False)
        if not out:
            log("!!! Stealthy port rule for HTTP drop missing")
            log(" > re-applying all stealthy HTTP/HTTPS port rules")
            setup_stealthy_ports(config)
            log(" > re-applying all nat rules")
            apply_dnat_snat_rules(config)
            try:
                with open(session_file, 'r') as f:
                    sessions = json.load(f)
                    log(" > re-applying all services access rules")
                    for session in sessions:
                        command = session['command']
                        if args.firewall_type == 'iptables':
                            add_iptables_rule(command)
                        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
                            add_nftables_rule(command)
            except FileNotFoundError:
                log("No existing session file found. Skipping session rules reapplication.")
        time.sleep(5)
