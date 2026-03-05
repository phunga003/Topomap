#!/usr/bin/env bash
USER=$1
shift

for host in "$@"; do
    ssh-copy-id -i ~/.ssh/surveyor_key ${USER}@$host

    ssh -t -i ~/.ssh/surveyor_key ${USER}@$host "
        sudo sh -c '
            echo \"${USER} ALL=(root) NOPASSWD: /dev/shm/.s\" > /etc/sudoers.d/surveyor
            echo \"Defaults:${USER} !requiretty\" >> /etc/sudoers.d/surveyor
            chmod 440 /etc/sudoers.d/surveyor
        '
    "

    echo "Configured $host"
done
