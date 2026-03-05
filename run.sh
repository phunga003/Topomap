#!/usr/bin/env bash

SCRIPT_DIR=$(dirname "$0")
SURVEYOR_BIN="${SCRIPT_DIR}/build/bin/surveyor"
SCAN_BIN="${SCRIPT_DIR}/build/bin/scan"
SETUP_SCRIPT="${SCRIPT_DIR}/setup_keys.sh"

USER=$1
shift

if [ $# -eq 0 ]; then
    echo "Usage: $0 <user> <ip1> <ip2> ..."
    exit 1
fi

if [ ! -f "$SURVEYOR_BIN" ]; then
    echo "Surveyor binary not found. Building..."
    mkdir -p build && cd build && cmake .. && make && cd ..
fi

if [ ! -f ~/.ssh/surveyor_key ]; then
    echo "Generating SSH key..."
    ssh-keygen -t ed25519 -f ~/.ssh/surveyor_key -N ""
fi

echo "=== Setting up keys ==="
sh "$SETUP_SCRIPT" "$USER" "$@"

echo "=== Scanning targets ==="
$SCAN_BIN "$USER" "$@"

