import re
import sys
from utils import log, log_err, execute_command, execute_command_with_pipes, string_to_hex_and_bit_length, remove_prefix
from config import check_config_destinations_nonlocal
import textwrap

## iptables
def iptables_rule_exists(command, output=False, run_with_sudo=False):
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
            # command = f"{command_rules_list} | grep {comment} ; true"
            # log(f"Executing command: {command}")
            # rule = execute_command(command, print_command=False, print_output=False, run_with_sudo=run_with_sudo)
            command = f"{command_rules_list}"
            rule = execute_command_with_pipes(command=command_rules_list, command2=f"grep {comment}", print_command=False, print_output=False, run_with_sudo=run_with_sudo)
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

def add_iptables_rule(command, run_with_sudo=False):
    if not iptables_rule_exists(command, output=True, run_with_sudo=run_with_sudo):
        execute_command(command, run_with_sudo=run_with_sudo)

def delete_iptables_rule(command, run_with_sudo=False):
    if iptables_rule_exists(command, run_with_sudo=run_with_sudo):
        command = command.replace(' -A ', ' -D ')
        command = command.replace(' -I ', ' -D ')
        execute_command(command, run_with_sudo=run_with_sudo)

## nftables
def nftables_rule_exists(command, output=False, pattern=r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*comment\s\'([^\']+)\'', run_with_sudo=False):
    # searches rule comment or name
    match = re.search(pattern, command)
    if match:
        table = match.group(1)
        chain = match.group(2)
        grep_pattern = match.group(3)
        command_nft_list = f"nft -a list chain ip {table} {chain}"
        try:
            command1 = f"{command_nft_list}"
            command2 = f"grep {grep_pattern}"
            command3 = "grep handle"
            try:
                rule = execute_command_with_pipes(command=command1, command2=command2, command3=command3, print_command=False, print_output=False, run_with_sudo=run_with_sudo)
            except Exception:
                # If grep doesn't find anything, it will return non-zero exit code, which is expected
                # This is equivalent to the "; true" that was in the original command
                rule = ""
            if rule:
                if output:
                    log(f"Rule exists : '{rule}'")
                handle = rule.split()[-1]
                return handle
            else:
                return False
        except Exception as e:
            log_err(f"Error: {e}")
    else:
        log_err(f"nftables : regex parsing of command failed : {command}")

def add_nftables_rule(command, run_with_sudo=False):
    if not nftables_rule_exists(command, output=True, run_with_sudo=run_with_sudo):
        execute_command(command, run_with_sudo=run_with_sudo)

def delete_nftables_rule(command, run_with_sudo=False):
    # with nftables you can't just replace 'add' with 'del' like it's done with iptables, it's more complicated , you need to list all the rules of a table, find the one to delete, take the handle number and then delete that handle.
    # nft delete rule ip vyos_filter NAME_IN-OpenVPN-KnockPort handle $(nft -a list table ip vyos_filter | grep "ipv4-NAM-IN-OpenVPN-KnockPort-tmp-127.0.0.1" | grep "handle" | awk '{print $NF}')
    # Regex pattern to capture the 5th word, 6th word, and the last quoted word
    handle = nftables_rule_exists(command, run_with_sudo=run_with_sudo)
    if handle:
        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+).*comment\s\'([^\']+)\''
        match = re.search(pattern, command)
        if match:
            table = match.group(1)
            chain = match.group(2)
            execute_command(f"nft delete rule ip {table} {chain} handle {handle}", run_with_sudo=run_with_sudo)
        else:
            log_err(f"nftables : No rule match found for : {command}")

def cleanup_firewall(sessions, firewall_type, run_with_sudo=False):
    # Clean up firewall rules for all active sessions
    for session in sessions:
        if firewall_type == 'iptables':
            command = session['command'].replace(' -A ', ' -D ')
            delete_iptables_rule(command, run_with_sudo=run_with_sudo)
        elif firewall_type == 'nftables' or firewall_type == 'vyos':
            delete_nftables_rule(session['command'], run_with_sudo=run_with_sudo)

def setup_stealthy_ports(config, args, app):
    # Set up the initial firewall rules for stealthy ports
    firewall_commands = []
    http_port = args.waf_http_port if args.waf_http_port else args.http_port
    https_port = args.waf_https_port if args.waf_https_port else args.https_port
    public_server_label = "WAF" if args.waf_http_port else "KnockPort"

    # nftables doesn't have string module like iptables, so we need to match hex characters on exact positions inside the TCP packet payload
    http_post_phase1_hex_string, http_post_phase1_hex_string_bit_length = string_to_hex_and_bit_length(f"POST {app.config['config']['global']['http_post_path']}")

    if args.firewall_type == 'iptables':
        firewall_commands = [
            f"echo Drop incoming packets to {public_server_label} HTTP port",
                f"iptables -I INPUT -i {config['global']['interface_ext']} -p tcp --dport {http_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-drop'",
            f"echo Allow incoming POST {app.config['config']['global']['http_post_path']} TCP packets to {public_server_label} HTTP port limited to 500B",
            # The --algo bm --to options specify using the Boyer-Moore algorithm to search for the string within the first N bytes of the packet payload, and the -m length --length 0:500 part restricts the rule to packets whose total length is between 0 and 500 bytes (HTTP request for Knock-Port should never exceed 500B)
                f"iptables -I INPUT -i {config['global']['interface_ext']} -p tcp --dport {http_port} -m string --string 'POST {app.config['config']['global']['http_post_path']}' --algo bm --to {http_post_phase1_hex_string_bit_length} -m length --length 0:500 -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-POST-path-{app.config['config']['global']['http_post_path'].replace('/', '_')}-accept'",
            f"echo Allow incoming SYN packets to {public_server_label} HTTP port for initial three-way TCP handshake",
                f"iptables -I INPUT -i {config['global']['interface_ext']} -p tcp --dport {http_port} --tcp-flags ALL SYN -j ACCEPT -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-SYN-accept'",
            f"echo Drop outgoing traffic from {public_server_label} HTTP port , allow only packets for initial handshake so Flask is able to handle the request . Client/curl will not receive a response from HTTP port",
                f"iptables -I OUTPUT -o {config['global']['interface_int']} -p tcp --sport {http_port} -j DROP -m comment --comment 'ipv4-OUT-KnockPort-{config['global']['interface_int']}-tcp-sport-{http_port}-drop'",
                f"iptables -I OUTPUT -o {config['global']['interface_int']} -p tcp --sport {http_port} --tcp-flags ALL SYN,ACK -j ACCEPT -m comment --comment 'ipv4-OUT-KnockPort-{config['global']['interface_int']}-tcp-sport-{http_port}-syn-ack-accept'",
            f"echo Drop incoming packets to {public_server_label} HTTPS port. Per IP allow rules will be created on request to {public_server_label} HTTP port",
                f"iptables -I INPUT -i {config['global']['interface_ext']} -p tcp --dport {https_port} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{https_port}-drop'"
        ]

        for app_name, app_config in config.items():
            if app_name != "global":
                if app_config['destination'] == "local":
                    firewall_commands.append("echo Drop incoming packets to Services ports")
                    firewall_commands.append(f"iptables -I INPUT -i {config['global']['interface_ext']} -p {app_config['protocol']} --dport {app_config['port']} -j DROP -m comment --comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                else:
                    interface_ext = app_config.get('interface_ext', config['global']['interface_ext'])
                    firewall_commands.append("echo Drop incoming packets to forwarded Services ports")
                    firewall_commands.append(f"iptables -I FORWARD -i {interface_ext} -p {app_config['protocol']} --dport {app_config['port']} -j DROP -m comment --comment 'ipv4-FWD-KnockPort-{config['global']['interface_ext']}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")

        for command in firewall_commands:
            if re.search(r"iptables -(A|I)", command):
                add_iptables_rule(command, run_with_sudo=args.run_with_sudo)
            else:
                execute_command(f"{command}", False)

    elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
        # vyos 'set' commands add "NAME_" prefix to the chain name for the nftables chain
        nftables_chain_input = remove_prefix(args.nftables_chain_input, "NAME_")
        nftables_chain_forward = remove_prefix(args.nftables_chain_forward, "NAME_")

        # initialize tables and chains if missing
        if args.firewall_type == 'nftables':
            nft_list_ruleset = execute_command(f"nft list ruleset", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo)
            if not f"table ip {args.nftables_table_filter}" + " {" in nft_list_ruleset:
                execute_command(f"nft add table ip {args.nftables_table_filter}", run_with_sudo=args.run_with_sudo)
            if not f"chain {args.nftables_chain_default_input}" + " {" in nft_list_ruleset:
                execute_command(f"nft add chain ip {args.nftables_table_filter} {args.nftables_chain_default_input}" + " '{ type filter hook input priority filter; policy accept; }'", run_with_sudo=args.run_with_sudo)
            if not f"chain {args.nftables_chain_default_output}" + " {" in nft_list_ruleset:
                execute_command(f"nft add chain ip {args.nftables_table_filter} {args.nftables_chain_default_output}" + " '{ type filter hook output priority filter; policy accept; }'", run_with_sudo=args.run_with_sudo)
            if not f"chain {args.nftables_chain_default_forward}" + " {" in nft_list_ruleset:
                execute_command(f"nft add chain ip {args.nftables_table_filter} {args.nftables_chain_default_forward}" + " '{ type filter hook forward priority filter; policy accept; }'", run_with_sudo=args.run_with_sudo)

            nft_list_ruleset = execute_command(f"nft list ruleset", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo)
            if not f"chain {args.nftables_chain_input}" + " {" in nft_list_ruleset:
                log(f"filter chain {args.nftables_chain_input} missing, creating it")
                execute_command(f"nft add chain ip {args.nftables_table_filter} {args.nftables_chain_input}", run_with_sudo=args.run_with_sudo)
                add_nftables_rule(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_input} counter continue comment 'ipv4-in-KnockPort-continue'", run_with_sudo=args.run_with_sudo)
                add_nftables_rule(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} counter jump {args.nftables_chain_input} comment 'ipv4-in-KnockPort-jump-to-{args.nftables_chain_input}'", run_with_sudo=args.run_with_sudo)
            if not f"chain {args.nftables_chain_forward}" + " {" in nft_list_ruleset:
                log(f"filter chain {args.nftables_chain_forward} missing, creating it")
                execute_command(f"nft add chain ip {args.nftables_table_filter} {args.nftables_chain_forward}", run_with_sudo=args.run_with_sudo)
                add_nftables_rule(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_forward} counter continue comment 'ipv4-in-KnockPort-continue'", run_with_sudo=args.run_with_sudo)
                add_nftables_rule(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_forward} counter jump {args.nftables_chain_forward} comment 'ipv4-in-KnockPort-jump-to-{args.nftables_chain_forward}'", run_with_sudo=args.run_with_sudo)

        elif args.firewall_type == 'vyos':
            nft_list_ruleset = execute_command(f"nft list ruleset", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo)
            if not f"chain {args.nftables_chain_input}" + " {" in nft_list_ruleset:
                log(f"Filter chain {args.nftables_chain_input} missing, running vyos 'set firewall' commands to create it")
                command = textwrap.dedent(f"""\
                    sudo -u vyos vbash -c '
                        source /opt/vyatta/etc/functions/script-template
                        configure
                        echo "Create chain {nftables_chain_input} with default continue rule"
                        set firewall ipv4 name {nftables_chain_input} default-action continue
                        set firewall ipv4 input filter rule 9999 action jump
                        set firewall ipv4 input filter rule 9999 jump-target {nftables_chain_input}
                        echo "Create chain {nftables_chain_forward} with default continue rule"
                        set firewall ipv4 name {nftables_chain_forward} default-action continue
                        set firewall ipv4 forward filter rule 9999 action jump
                        set firewall ipv4 forward filter rule 9999 jump-target {nftables_chain_forward}
                        commit
                    '
                """)
                if args.run_with_sudo:
                    log("WARNING: You're running with --run-with-sudo, you need to manually run the following command to initialize the filter chain, since you're probably running under a limited-permission user that can't run 'sudo -u vyos vbash'")
                    log(command)
                    sys.exit(1)
                else:
                    execute_command(command)
            else:
                log(f"Filter chain {args.nftables_chain_input} present")

        # set up stealth rules
        firewall_commands = firewall_commands + [
            f"echo Drop incoming packets to {public_server_label} HTTP port"
        ]
        if args.firewall_type == 'nftables' :
            try:
                output_lines_count = execute_command_with_pipes(command=f"nft list chain {args.nftables_table_filter} {args.nftables_chain_default_input}", command2="wc -l", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo).strip()
            except Exception:
                output_lines_count = "0"
            if output_lines_count == "5" :
                # chain empty
                firewall_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} tcp dport {http_port} iifname {config['global']['interface_ext']} counter drop comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-drop'")
            else:
                firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {http_port} iifname {config['global']['interface_ext']} counter drop comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-drop'")
        elif args.firewall_type == 'vyos' :
            # vyos nft chains are never empty
            firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {http_port} iifname {config['global']['interface_ext']} counter drop comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-drop'")

        firewall_commands = firewall_commands + [
            # we're adding rules with insert so the final order will be opposite of the order here
            f"echo Allow incoming POST {app.config['config']['global']['http_post_path']} TCP packets to {public_server_label} HTTP port limited to 500B",
                # @ih,0,N from here : https://manpages.debian.org/bookworm/nftables/nft.8.en.html#RAW_PAYLOAD_EXPRESSION
                # restricts the rule to packets whose total length is between 0 and 500 bytes (HTTP request for Knock-Port should never exceed 500B) and whose payload starts with 'POST ' + http_post_phase1_hex_string.
                f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {http_port} ip length 0-500 @ih,0,{http_post_phase1_hex_string_bit_length} == 0x{http_post_phase1_hex_string} iifname {config['global']['interface_ext']} counter accept comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-POST-path-{app.config['config']['global']['http_post_path'].replace('/', '_')}-accept'",
            f"echo Allow incoming SYN packets to {public_server_label} HTTP port for initial three-way TCP handshake",
                f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {http_port} 'tcp flags & (fin|syn|rst|ack) == syn' iifname {config['global']['interface_ext']} counter accept comment 'ipv4-IN-KnockPort-{config['global']['interface_ext']}-tcp-dport-{http_port}-SYN-accept'"
        ]

        firewall_commands = firewall_commands + [
            f"echo Drop outgoing traffic from {public_server_label} HTTP port , allow only TCP packets for initial three-way TCP handshake so web-server is able to handle the request . Client will not receive a HTTP response"
        ]
        if args.firewall_type == 'nftables' :
            try:
                output_lines_count = execute_command_with_pipes(command=f"nft list chain {args.nftables_table_filter} {args.nftables_chain_default_output}", command2="wc -l", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo).strip()
            except Exception:
                output_lines_count = "0"
            if output_lines_count == "5" :
                # chain empty
                firewall_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_output} tcp sport {http_port} oifname {config['global']['interface_int']} counter drop comment 'ipv4-OUT-KnockPort-{config['global']['interface_int']}-tcp-sport-{http_port}-drop'")
            else:
                firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_output} index 0 tcp sport {http_port} oifname {config['global']['interface_int']} counter drop comment 'ipv4-OUT-KnockPort-{config['global']['interface_int']}-tcp-sport-{http_port}-drop'")
        elif args.firewall_type == 'vyos' :
            # vyos nft chains are never empty
            firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_output} index 0 tcp sport {http_port} oifname {config['global']['interface_int']} counter drop comment 'ipv4-OUT-KnockPort-{config['global']['interface_int']}-tcp-sport-{http_port}-drop'")

        firewall_commands = firewall_commands + [
                f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_output} index 0 tcp sport {http_port} 'tcp flags & (syn|ack) == syn|ack' oifname {config['global']['interface_int']} counter accept comment 'ipv4-OUT-KnockPort-{config['global']['interface_int']}-tcp-sport-{http_port}-syn-ack-accept'"
        ]

        if args.firewall_type == 'nftables':
            firewall_commands = firewall_commands + [
                f"echo Drop incoming packets to {public_server_label} HTTPS port. Per IP allow rules will be created on request to {public_server_label} HTTP port"
            ]
            if args.nftables_chain_input == args.nftables_chain_default_input:
                firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} index 0 tcp dport {https_port} iifname {config['global']['interface_ext']} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{https_port}-drop'")
            else:
                firewall_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} tcp dport {https_port} iifname {config['global']['interface_ext']} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{https_port}-drop'")

            for app_name, app_config in config.items():
                if app_name != "global":
                    interface_ext = app_config.get('interface_ext', config['global']['interface_ext'])
                    interface_int = app_config.get('interface_int', config['global']['interface_int'])
                    if app_config['destination'] == "local":
                        firewall_commands = firewall_commands + [
                            "echo Drop incoming packets to Services ports"
                        ]
                        if args.nftables_chain_input == args.nftables_chain_default_input:
                            firewall_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_input} {app_config['protocol']} dport {app_config['port']} iifname {interface_ext} counter drop comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                        else:
                            continue_command = f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_input} counter continue comment 'ipv4-in-KnockPort-continue'"
                            pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+(continue)\s+.+'
                            continue_command_handle = nftables_rule_exists(continue_command, False, pattern, run_with_sudo=args.run_with_sudo)
                            if continue_command_handle:
                                firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} handle {continue_command_handle} {app_config['protocol']} dport {app_config['port']} iifname {interface_ext} counter drop comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                            else:
                                log(f"Error: Can't find the continue rule in chain {args.nftables_table_filter} {args.nftables_chain_input}")
                                sys.exit(1)
                    else:
                        firewall_commands = firewall_commands + [
                            "echo Drop incoming packets to forwarded Services ports"
                        ]
                        if args.nftables_chain_input == args.nftables_chain_default_input:
                            firewall_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_forward} {app_config['protocol']} dport {app_config['port']} oifname {interface_int} counter drop comment 'ipv4-FWD-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                        else:
                            continue_command = f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_forward} counter continue comment 'ipv4-in-KnockPort-continue'"
                            pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+(continue)\s+.+'
                            continue_command_handle = nftables_rule_exists(continue_command, False, pattern, run_with_sudo=args.run_with_sudo)
                            if continue_command_handle:
                                firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_forward} handle {continue_command_handle} {app_config['protocol']} dport {app_config['port']} oifname {interface_int} counter drop comment 'ipv4-FWD-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                            else:
                                log(f"Error: Can't find the continue rule in chain {args.nftables_table_filter} {args.nftables_chain_forward}")
                                sys.exit(1)

        elif args.firewall_type == 'vyos':
            firewall_commands = firewall_commands + [
                f"echo Drop incoming packets to {public_server_label} HTTPS port. Per IP allow rules will be created on request to {public_server_label} HTTP port",
            ]
            # looking for the jump rule to the separate chain args.nftables_chain_input or args.nftables_chain_forward , we need to add this drop rule after the jump rule
            jump_command = f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} counter jump {args.nftables_chain_input} comment 'none'"
            pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+jump\s+(\S+)\s+comment\s.+'
            jump_command_handle = nftables_rule_exists(jump_command, False, pattern, run_with_sudo=args.run_with_sudo)
            if jump_command_handle:
                firewall_commands.append(f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_default_input} handle {jump_command_handle} tcp dport {https_port} counter drop comment 'ipv4-IN-KnockPort-tcp-dport-{https_port}-drop'")
            else:
                log(f"Error: Can't find the jump rule to {args.nftables_chain_input} in chain {args.nftables_table_filter} {args.nftables_chain_default_input}")
                sys.exit(1)

            for app_name, app_config in config.items():
                if app_name != "global":
                    interface_ext = app_config.get('interface_ext', config['global']['interface_ext'])
                    interface_int = app_config.get('interface_int', config['global']['interface_int'])
                    if app_config['destination'] == "local":
                        firewall_commands = firewall_commands + [
                            "echo Drop incoming packets to Services ports"
                        ]
                        continue_command = f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_input} counter continue comment 'ipv4-in-KnockPort-continue'"
                        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+(continue)\s+.+'
                        continue_command_handle = nftables_rule_exists(continue_command, False, pattern, run_with_sudo=args.run_with_sudo)
                        if continue_command_handle:
                            firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_input} handle {continue_command_handle} {app_config['protocol']} dport {app_config['port']} iifname {interface_ext} counter drop comment 'ipv4-IN-KnockPort-{interface_ext}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                        else:
                            log(f"Error: Can't find the continue rule in chain {args.nftables_table_filter} {args.nftables_chain_input}")
                            sys.exit(1)
                    else:
                        firewall_commands = firewall_commands + [
                            "echo Drop incoming packets to forwarded Services ports"
                        ]
                        continue_command = f"nft add rule ip {args.nftables_table_filter} {args.nftables_chain_forward} counter continue comment 'ipv4-in-KnockPort-continue'"
                        pattern = r'^\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s+(\S+)\s+\S+\s+(continue)\s+.+'
                        continue_command_handle = nftables_rule_exists(continue_command, False, pattern, run_with_sudo=args.run_with_sudo)
                        if continue_command_handle:
                            firewall_commands.append(f"nft insert rule ip {args.nftables_table_filter} {args.nftables_chain_forward} handle {continue_command_handle} {app_config['protocol']} dport {app_config['port']} oifname {interface_int} counter drop comment 'ipv4-FWD-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{app_config['port']}-drop'")
                        else:
                            log(f"Error: Can't find the continue rule in chain {args.nftables_table_filter} {args.nftables_chain_forward}")
                            sys.exit(1)

        for command in firewall_commands:
            if re.search(r"nft (add|insert) rule", command):
                add_nftables_rule(command, run_with_sudo=args.run_with_sudo)
            else:
                execute_command(f"{command}", False)

    return firewall_commands

def cleanup_stealthy_ports(firewall_commands, args):
    # Clean up the firewall rules for stealthy ports
    for command in firewall_commands:
        if args.firewall_type == 'iptables':
            if re.search(r"iptables -(A|I)", command):
                delete_iptables_rule(command, run_with_sudo=args.run_with_sudo)
        elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
            if re.search(r"nft (add|insert) rule", command):
                delete_nftables_rule(command, run_with_sudo=args.run_with_sudo)

def apply_nat_rules(config, args):
    if check_config_destinations_nonlocal(config):
        log("Setting up forwarding (at least one of the configured services has non-local destination):")
        for app_name, app_config in config.items():
            if app_name != "global":
                if app_config['destination'] != "local":
                    interface_int = app_config.get('interface_int', config['global']['interface_int'])
                    destination_parts = app_config['destination'].split(':')
                    destination_ip = destination_parts[0]
                    destination_port = destination_parts[1] if len(destination_parts) > 1 else app_config['port']
                    if args.firewall_type == 'iptables':
                        add_iptables_rule(f"iptables -t nat -A POSTROUTING -o {interface_int} -p {app_config['protocol']} -d {destination_ip} --dport {destination_port} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{destination_ip}-{destination_port}-MASQUERADE'", run_with_sudo=args.run_with_sudo)

                    # initialize tables and chains if missing
                    if args.firewall_type == 'nftables':
                        nft_list_ruleset = execute_command(f"nft list ruleset", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo)
                        if not f"table ip {args.nftables_table_nat}" + " {" in nft_list_ruleset:
                            execute_command(f"nft add table ip {args.nftables_table_nat}", run_with_sudo=args.run_with_sudo)
                        if not f"chain {args.nftables_chain_default_prerouting}" + " {" in nft_list_ruleset:
                            execute_command(f"nft add chain ip {args.nftables_table_nat} {args.nftables_chain_default_prerouting}" + " '{ type nat hook prerouting priority dstnat; policy accept; }'", run_with_sudo=args.run_with_sudo)
                        if not f"chain {args.nftables_chain_default_postrouting}" + " {" in nft_list_ruleset:
                            execute_command(f"nft add chain ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting}" + " '{ type nat hook postrouting priority srcnat; policy accept; }'", run_with_sudo=args.run_with_sudo)

                    if args.firewall_type == 'vyos':
                        nft_list_ruleset = execute_command(f"nft list ruleset", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo)
                        if not f"table ip {args.nftables_table_nat}" + " {" in nft_list_ruleset:
                            log("NAT table missing, running vyos 'set nat destination' non-functional commands to initialize NAT chains")
                            command = textwrap.dedent("""\
                                sudo -u vyos vbash -c '
                                    source /opt/vyatta/etc/functions/script-template
                                    configure
                                    set nat destination rule 101 description 'blank-DNAT-rule'
                                    set nat destination rule 101 destination port '65535'
                                    set nat destination rule 101 inbound-interface name 'eth0'
                                    set nat destination rule 101 protocol 'tcp'
                                    set nat destination rule 101 translation address '10.255.255.254'
                                    set nat destination rule 101 translation port '65535'
                                    commit
                                    del nat destination rule 101
                                    commit
                                '
                            """)
                            if args.run_with_sudo:
                                log("WARNING: You're running with --run-with-sudo, you need to manually run the following command to initialize the NAT chains, since you're probably running under a limited-permission user that can't run 'sudo -u vyos vbash'")
                                log(command)
                                sys.exit(1)
                            else:
                                execute_command(command)
                        else:
                            log("NAT table present")

                    # adding NAT rules for each non-local destination
                    if args.firewall_type == 'nftables' :
                        try:
                            output_lines_count = execute_command_with_pipes(command=f"nft list chain {args.nftables_table_nat} {args.nftables_chain_default_postrouting}", command2="wc -l", print_command=False, print_output=False, run_with_sudo=args.run_with_sudo).strip()
                        except Exception:
                            output_lines_count = "0"
                        if output_lines_count == "5" :
                            # chain empty
                            add_nftables_rule(f"nft add rule ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting} {app_config['protocol']} dport {destination_port} ip daddr {destination_ip} oifname {interface_int} counter masquerade comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{destination_ip}-{destination_port}-MASQUERADE'", run_with_sudo=args.run_with_sudo)
                        else:
                            add_nftables_rule(f"nft insert rule ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting} index 0 {app_config['protocol']} dport {destination_port} ip daddr {destination_ip} oifname {interface_int} counter masquerade comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{destination_ip}-{destination_port}-MASQUERADE'", run_with_sudo=args.run_with_sudo)
                    elif args.firewall_type == 'vyos' :
                        # vyos nft chains are never empty
                        add_nftables_rule(f"nft insert rule ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting} index 0 {app_config['protocol']} dport {destination_port} ip daddr {destination_ip} oifname {interface_int} counter masquerade comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{destination_ip}-{destination_port}-MASQUERADE'", run_with_sudo=args.run_with_sudo)

def cleanup_nat_rules(config, args):
    if check_config_destinations_nonlocal(config):
        for app_name, app_config in config.items():
            if app_name != "global":
                if app_config['destination'] != "local":
                    interface_int = app_config.get('interface_int', config['global']['interface_int'])
                    destination_parts = app_config['destination'].split(':')
                    destination_ip = destination_parts[0]
                    destination_port = destination_parts[1] if len(destination_parts) > 1 else app_config['port']
                    if args.firewall_type == 'iptables':
                        delete_iptables_rule(f"iptables -t nat -A POSTROUTING -o {interface_int} -p {app_config['protocol']} -d {destination_ip} --dport {destination_port} -j MASQUERADE -m comment --comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{destination_ip}-{destination_port}-MASQUERADE'", run_with_sudo=args.run_with_sudo)
                    elif args.firewall_type == 'nftables' or args.firewall_type == 'vyos':
                        delete_nftables_rule(f"nft add rule ip {args.nftables_table_nat} {args.nftables_chain_default_postrouting} {app_config['protocol']} dport {destination_port} ip daddr {destination_ip} oifname {interface_int} counter masquerade comment 'ipv4-POSTROUTING-KnockPort-{interface_int}-{app_name}-{app_config['protocol']}-{destination_ip}-{destination_port}-MASQUERADE'", run_with_sudo=args.run_with_sudo)
