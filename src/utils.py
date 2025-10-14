import time
import sys
from sh import bash, sudo
import subprocess
import shlex
import pprint
pp = pprint.PrettyPrinter(indent=4)
# > pp.pprint

def log(text):
    message = "%s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
    print(message, end='', flush=True)

def log_err(text):
    message = "%s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
    print(message, end='', file=sys.stderr, flush=True)

def execute_command_with_pipes(command, command2, command3=None , print_command=True, print_output=True, run_with_sudo=False):
    # print_command=True
    # print_output=True
    # log(f"print_command: {print_command}, print_output: {print_output}, run_with_sudo: {run_with_sudo}, command: {command}, command2: {command2}")
    if run_with_sudo:
        if print_command:
            log(f"Executing command: sudo {command}")
        if command.startswith("echo "):
            out=str(bash('-c', command)).strip()
        else:
            # out=str(bash('-c', f"bash src/wrapper.sh sudo {command}")).strip()
            # out=str(bash('-c', f"sudo {command}")).strip()
            # out=str(sudo(command)).strip()
            if command.startswith("iptables "):
                command = command.replace('iptables', '/usr/sbin/iptables')
            if command.startswith("nftables "):
                command = command.replace('nftables', '/usr/sbin/nftables')

            # Only the first command needs sudo, grep/wc commands don't need elevated privileges
            command_process = subprocess.Popen(["sudo"] + command.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            command2_process = subprocess.Popen(command2.split(" "), stdin=command_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            command_process.stdout.close()
            out, errors = command2_process.communicate()
            out = out.decode()
            errors = errors.decode()
            if command3:
                command_process = subprocess.Popen(["sudo"] + command.split(" "), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                command2_process = subprocess.Popen(command2.split(" "), stdin=command_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                command_process.stdout.close()
                command3_process = subprocess.Popen(command3.split(" "), stdin=command2_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                command2_process.stdout.close()
                out, errors = command3_process.communicate()
                out = out.decode()
                errors = errors.decode()

    else:
        if print_command:
            log(f"Executing command: {command}")
        out=str(bash('-c', command)).strip()
    if out:
        if print_output:
            log(out)
    return out

def execute_command(command, print_command=True, print_output=True, run_with_sudo=False):
    # log(f"print_command: {print_command}, print_output: {print_output}, run_with_sudo: {run_with_sudo}, command: {command}")
    if run_with_sudo:
        if print_command:
            log(f"Executing command: sudo {command}")
        if command.startswith("echo "):
            out=str(bash('-c', command)).strip()
        else:
            if command.startswith("iptables "):
                command = command.replace('iptables', '/usr/sbin/iptables')
            if command.startswith("nftables "):
                command = command.replace('nftables', '/usr/sbin/nftables')
            command_args = shlex.split(command)
            out=str(sudo(*command_args, _tty_out=True)).strip()
            # out=str(bash('-c', f"bash src/wrapper.sh sudo {command}")).strip()
            # out=str(bash('-c', f"sudo {command}")).strip()
    else:
        if print_command:
            log(f"Executing command: {command}")
        out=str(bash('-c', command)).strip()
    if out:
        if print_output:
            log(out)
    return out

def string_to_hex_and_bit_length(input_string):
    # Convert string to bytes, then to hexadecimal
    hex_representation = input_string.encode().hex()
    # Calculate the bit length
    bit_length = len(hex_representation) * 4  # Each hex digit represents 4 bits
    return hex_representation, bit_length

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text
