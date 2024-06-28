#!/bin/bash

# Function to delete a rule based on partial match
nft_delete_rule() {
    local table="$1"
    local chain="$2"
    local match="$3"
    echo "Searching for rules in $table -> $chain matching '$match'..."

    # List rules with handles, match rule, get handle
    local handles=($(nft -a list table ip $table | grep "$match" | grep "handle" | awk '{print $NF}'))

    # Check if handles were found
    if [ ${#handles[@]} -eq 0 ]; then
        echo "No matching rules found."
        return 1
    fi

    # Confirm before deleting
    echo "Found ${#handles[@]} rules to delete."
    for handle in "${handles[@]}"; do
        echo "Deleting rule with handle $handle..."
        echo nft delete rule ip $table $chain handle $handle
    done
}

# Usage example: nft_delete_rule "vyos_filter" "NAME_IN-OpenVPN-KnockPort" "tcp dport 1194"
# nft_delete_rule "vyos_filter" "NAME_IN-OpenVPN-KnockPort" "$@"
