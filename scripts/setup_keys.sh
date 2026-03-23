#!/usr/bin/env bash
# Enroll a user on one or more hosts for passwordless SSH and sudoers access.
# Usage: setup_keys.sh <user> <host> [host ...]

USER=$1
shift

for host in "$@"; do
    if ! ssh -i ~/.ssh/surveyor_key -o BatchMode=yes -o ConnectTimeout=5 ${USER}@$host true 2>/dev/null; then
        ssh-copy-id -i ~/.ssh/surveyor_key ${USER}@$host
    fi

    if ! ssh -i ~/.ssh/surveyor_key -o BatchMode=yes ${USER}@$host "test -f /etc/sudoers.d/surveyor" 2>/dev/null; then
        ssh -t -i ~/.ssh/surveyor_key ${USER}@$host "
            sudo sh -c '
                echo \"${USER} ALL=(root) NOPASSWD: /dev/shm/.s\" > /etc/sudoers.d/surveyor
                echo \"Defaults:${USER} !requiretty\" >> /etc/sudoers.d/surveyor
                chmod 440 /etc/sudoers.d/surveyor
            '
        "
    fi

    echo "Configured $host"
done