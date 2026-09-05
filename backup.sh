#!/bin/bash
# Backup / restore the OpenVPN server environment (PKI, profiles, configs, UI database).
set -euo pipefail

usage() {
    echo -e "\n\033[1mBackup or restore of the OpenVPN server environment\033[0m"
    echo -e "  \033[1;32mBackup:\033[0m  sudo ./backup.sh -b <server dir> <backup dir>"
    echo -e "  \033[1;34mRestore:\033[0m sudo ./backup.sh -r <server dir> <backup dir>\n"
    echo -e "  Example: sudo ./backup.sh -b ~/openvpn-server ~/backup/openvpn-$(date +%F)\n"
    exit 1
}

[[ $# -eq 3 ]] || usage
ACTION=$1
SERVER_ENV=${2%/}
BACKUP_DIR=${3%/}

ITEMS=(server.conf config pki clients staticclients db fw-rules.sh docker-compose.yml .env)

case $ACTION in
    -b)
        read -p "Back up \"$SERVER_ENV\" to \"$BACKUP_DIR\"? (y/n) " -n 1 -r; echo
        [[ $REPLY =~ ^[Yy]$ ]] || { echo -e "\033[1;31mCancelled\033[0m"; exit 1; }
        mkdir -p "$BACKUP_DIR"
        for item in "${ITEMS[@]}"; do
            if [[ -e $SERVER_ENV/$item ]]; then
                cp -Rp "$SERVER_ENV/$item" "$BACKUP_DIR/"
                echo " $item backed up"
            fi
        done
        echo -e "\033[1;32mBackup created at $BACKUP_DIR\033[0m"
        ;;
    -r)
        read -p "Replace the environment in \"$SERVER_ENV\" with \"$BACKUP_DIR\"? (y/n) " -n 1 -r; echo
        [[ $REPLY =~ ^[Yy]$ ]] || { echo -e "\033[1;31mCancelled\033[0m"; exit 1; }
        for item in "${ITEMS[@]}"; do
            if [[ -e $BACKUP_DIR/$item ]]; then
                rm -rf "${SERVER_ENV:?}/$item"
                cp -Rp "$BACKUP_DIR/$item" "$SERVER_ENV/"
                echo " $item restored"
            fi
        done
        echo -e "\033[1;34mRestore completed. Run: docker compose up -d\033[0m"
        ;;
    *)
        usage
        ;;
esac
