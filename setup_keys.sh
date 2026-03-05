#!/usr/bin/env bash
PUBKEY=$(cat ~/.ssh/surveyor_key.pub)
USER=$1
shift


for host in "$@"; do
    ssh -t ${USER}@$host "
        if [ \"\$(id -u)\" = \"0\" ]; then
            FORCED_CMD=\"cat > /dev/shm/.s && chmod +x /dev/shm/.s && /dev/shm/.s && rm -f /dev/shm/.s\"
        else
            FORCED_CMD=\"cat > /dev/shm/.s && chmod +x /dev/shm/.s && sudo /dev/shm/.s && rm -f /dev/shm/.s\"
            echo '${USER} ALL=(root) NOPASSWD: /dev/shm/.s' | sudo tee /etc/sudoers.d/surveyor > /dev/null
            echo 'Defaults:${USER} !requiretty' | sudo tee -a /etc/sudoers.d/surveyor > /dev/null
            sudo chmod 440 /etc/sudoers.d/surveyor
        fi
        mkdir -p ~/.ssh &&
        echo \"command=\\\"\${FORCED_CMD}\\\",no-port-forwarding,no-x11-forwarding,no-agent-forwarding,no-pty ${PUBKEY}\" >> ~/.ssh/authorized_keys &&
        chmod 600 ~/.ssh/authorized_keys
    "
    echo "Configured $host"
done
