import time
import sys
from sh import bash

def log(text):
    message = "%s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
    print(message, end='', flush=True)

def log_err(text):
    message = "%s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), text)
    print(message, end='', file=sys.stderr, flush=True)

def execute_command(command, print_command=True, print_output=True):
    if print_command:
        log(f"Executing command: {command}")
    out=str(bash('-c', command, _tty_out=True)).strip()
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
