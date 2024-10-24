import re
import sys
from utils import log, log_err, execute_command

def iptables_rule_exists(command, output=False):
    pattern = r'^\S+\s+\S+\s+(\S+)\s+.*comment\s\'([^\']+)\''
    match = re.search(pattern, command)
    if match:
        table = match.group(1)
        if table == "nat":
            table = f"-t {table}"
        comment = match.group(2)
        command_rules_list = f"iptables -n -v -L {table}"
        try:
            command = f"{command_rules_list} | grep {comment} ; true"
            rule = execute_command(command, print_command=False, print_output=False)
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

def nftables_rule_exists(command, output=False, pattern=r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*comment\s\'([^\']+)\''):
    match = re.search(pattern, command)
    if match:
        table = match.group(1)
        chain = match.group(2)
        grep_pattern = match.group(3)
        command_nft_list = f"nft -a list chain ip {table} {chain}"
        try:
            command = f"{command_nft_list} | grep {grep_pattern} | grep handle ; true"
            rule = execute_command(command, print_command=False, print_output=False)
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
        execute_command(command)

def delete_nftables_rule(command):
    handle = nftables_rule_exists(command)
    if handle:
        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*comment\s\'([^\']+)\''
        match = re.search(pattern, command)
        if match:
            table = match.group(1)
            chain = match.group(2)
            execute_command(f"nft delete rule ip {table} {chain} handle {handle}")
        else:
            log_err(f"nftables : No rule match found for : {command}")

def cleanup_firewall(sessions, firewall_type):
    """Clean up firewall rules for all active sessions"""
    for session in sessions:
        if firewall_type == 'iptables':
            command = session['command'].replace(' -A ', ' -D ')
            delete_iptables_rule(command)
        elif firewall_type == 'nftables' or firewall_type == 'vyos':
            delete_nftables_rule(session['command'])

def setup_stealthy_ports(config, args, app):
    """Set up the initial firewall rules for stealthy ports"""
    firewall_commands = []
    interface_ext = config['global']['interface_ext']
    interface_int = config['global']['interface_int']

    if args.firewall_type == 'iptables':
        # HTTP port rules
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.http_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.http_port}-drop'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # Allow POST requests
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.http_port} -m string --string 'POST {config['global']['http_post_path']}' --algo bm --to 200 -m length --length 0:500 -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.http_port}-POST-path-{config['global']['http_post_path'].replace('/', '_')}-accept'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # Allow SYN packets
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.http_port} --tcp-flags ALL SYN -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.http_port}-SYN-accept'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # Drop outgoing traffic except handshake
        command = f"iptables -I OUTPUT -o {interface_int} -p tcp --sport {args.http_port} -j DROP -m comment --comment 'ipv4-OUT-KnockPort-{interface_int}-tcp-sport-{args.http_port}-drop'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        command = f"iptables -I OUTPUT -o {interface_int} -p tcp --sport {args.http_port} --tcp-flags ALL SYN,ACK -j ACCEPT -m comment --comment 'ipv4-OUT-KnockPort-{interface_int}-tcp-sport-{args.http_port}-syn-ack-accept'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # HTTPS port rules
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.https_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.https_port}-drop'"
        add_iptables_rule(command)
        firewall_commands.append(command)

    elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
        # Add nftables rules here following similar pattern
        pass

    return firewall_commands

def cleanup_stealthy_ports(firewall_commands, args):
    """Clean up the firewall rules for stealthy ports"""
    for command in firewall_commands:
        if args.firewall_type == 'iptables':
            delete_iptables_rule(command)
        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
            delete_nftables_rule(command)

def apply_nat_rules(config, args):
    """Apply NAT rules for non-local destinations"""
    for app_name, app_config in config.items():
        if app_name != "global" and app_config['destination'] != "local":
            interface_ext = app_config.get('interface_ext', config['global']['interface_ext'])
            interface_int = app_config.get('interface_int', config['global']['interface_int'])
            
            if args.firewall_type == 'iptables':
                # DNAT rule
                command = f"iptables -t nat -A PREROUTING -i {interface_ext} -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']} -m comment --comment 'ipv4-PREROUTING-KnockPort-{interface_ext}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'"
                add_iptables_rule(command)
                
                # MASQUERADE rule
                command = f"iptables -t nat -A POSTROUTING -o {interface_int} -p {app_config['protocol']} -d {app_config['destination']} --dport {app_config['port']} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'"
                add_iptables_rule(command)

def cleanup_nat_rules(config, args):
    """Clean up NAT rules for non-local destinations"""
    for app_name, app_config in config.items():
        if app_name != "global" and app_config['destination'] != "local":
            interface_ext = app_config.get('interface_ext', config['global']['interface_ext'])
            interface_int = app_config.get('interface_int', config['global']['interface_int'])
            
            if args.firewall_type == 'iptables':
                # Delete DNAT rule
                command = f"iptables -t nat -A PREROUTING -i {interface_ext} -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']} -m comment --comment 'ipv4-PREROUTING-KnockPort-{interface_ext}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'"
                delete_iptables_rule(command)
                
                # Delete MASQUERADE rule
                command = f"iptables -t nat -A POSTROUTING -o {interface_int} -p {app_config['protocol']} -d {app_config['destination']} --dport {app_config['port']} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'"
                delete_iptables_rule(command)

def setup_stealthy_ports(config, args, app):
    """Set up the initial firewall rules for stealthy ports"""
    firewall_commands = []
    interface_ext = config['global']['interface_ext']
    interface_int = config['global']['interface_int']

    if args.firewall_type == 'iptables':
        # HTTP port rules
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.http_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.http_port}-drop'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # Allow POST requests
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.http_port} -m string --string 'POST {config['global']['http_post_path']}' --algo bm --to 200 -m length --length 0:500 -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.http_port}-POST-path-{config['global']['http_post_path'].replace('/', '_')}-accept'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # Allow SYN packets
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.http_port} --tcp-flags ALL SYN -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.http_port}-SYN-accept'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # Drop outgoing traffic except handshake
        command = f"iptables -I OUTPUT -o {interface_int} -p tcp --sport {args.http_port} -j DROP -m comment --comment 'ipv4-OUT-KnockPort-{interface_int}-tcp-sport-{args.http_port}-drop'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        command = f"iptables -I OUTPUT -o {interface_int} -p tcp --sport {args.http_port} --tcp-flags ALL SYN,ACK -j ACCEPT -m comment --comment 'ipv4-OUT-KnockPort-{interface_int}-tcp-sport-{args.http_port}-syn-ack-accept'"
        add_iptables_rule(command)
        firewall_commands.append(command)

        # HTTPS port rules
        command = f"iptables -I INPUT -i {interface_ext} -p tcp --dport {args.https_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{interface_ext}-tcp-dport-{args.https_port}-drop'"
        add_iptables_rule(command)
        firewall_commands.append(command)

    elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
        # Similar rules for nftables
        # Add your nftables rules here following the same pattern
        pass

    return firewall_commands

def cleanup_stealthy_ports(firewall_commands, args):
    """Clean up the firewall rules for stealthy ports"""
    for command in firewall_commands:
        if args.firewall_type == 'iptables':
            delete_iptables_rule(command)
        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
            delete_nftables_rule(command)

def apply_nat_rules(config, args):
    """Apply NAT rules for non-local destinations"""
    for app_name, app_config in config.items():
        if app_name != "global" and app_config['destination'] != "local":
            interface_ext = app_config.get('interface_ext', config['global']['interface_ext'])
            interface_int = app_config.get('interface_int', config['global']['interface_int'])
            
            if args.firewall_type == 'iptables':
                # DNAT rule
                command = f"iptables -t nat -A PREROUTING -i {interface_ext} -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']} -m comment --comment 'ipv4-PREROUTING-KnockPort-{interface_ext}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'"
                add_iptables_rule(command)
                
                # MASQUERADE rule
                command = f"iptables -t nat -A POSTROUTING -o {interface_int} -p {app_config['protocol']} -d {app_config['destination']} --dport {app_config['port']} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'"
                add_iptables_rule(command)

def cleanup_nat_rules(config, args):
    """Clean up NAT rules for non-local destinations"""
    for app_name, app_config in config.items():
        if app_name != "global" and app_config['destination'] != "local":
            interface_ext = app_config.get('interface_ext', config['global']['interface_ext'])
            interface_int = app_config.get('interface_int', config['global']['interface_int'])
            
            if args.firewall_type == 'iptables':
                # Delete DNAT rule
                command = f"iptables -t nat -A PREROUTING -i {interface_ext} -p {app_config['protocol']} --dport {app_config['port']} -j DNAT --to-destination {app_config['destination']}:{app_config['port']} -m comment --comment 'ipv4-PREROUTING-KnockPort-{interface_ext}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-DNAT'"
                delete_iptables_rule(command)
                
                # Delete MASQUERADE rule
                command = f"iptables -t nat -A POSTROUTING -o {interface_int} -p {app_config['protocol']} -d {app_config['destination']} --dport {app_config['port']} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{app_config['destination']}-{app_config['port']}-MASQUERADE'"
                delete_iptables_rule(command)
