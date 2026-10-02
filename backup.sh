#!/bin/bash
# Backup / restore the OpenVPN server environment (PKI, profiles, configs, UI database).
#
# The web UI also writes an archive of the same files once a day into
# <server dir>/backups; -r restores from such an archive as well.
set -euo pipefail

usage() {
    echo -e "\n\033[1mBackup or restore of the OpenVPN server environment\033[0m"
    echo -e "  \033[1;32mBackup:\033[0m  sudo ./backup.sh [-y] -b <server dir> <backup dir>"
    echo -e "  \033[1;34mRestore:\033[0m sudo ./backup.sh [-y] -r <server dir> <backup dir | backup archive>\n"
    echo -e "  -y  do not ask for confirmation (for cron)"
    echo -e "  Example: sudo ./backup.sh -b ~/openvpn-server ~/backup/openvpn-$(date +%F)\n"
    exit 1
}

YES=0
if [[ ${1:-} == -y ]]; then YES=1; shift; fi
[[ $# -eq 3 ]] || usage
ACTION=$1
SERVER_ENV=${2%/}
BACKUP_DIR=${3%/}

ITEMS=(server.conf config pki clients staticclients guests db fw-rules.sh docker-compose.yml .env)
DB=db/openvpn-ui.db

confirm() {
    (( YES )) && return 0
    read -p "$1 (y/n) " -n 1 -r; echo
    [[ $REPLY =~ ^[Yy]$ ]] || { echo -e "\033[1;31mCancelled\033[0m"; exit 1; }
}

case $ACTION in
    -b)
        confirm "Back up \"$SERVER_ENV\" to \"$BACKUP_DIR\"?"
        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"       # it holds the CA key
        for item in "${ITEMS[@]}"; do
            if [[ -e $SERVER_ENV/$item ]]; then
                cp -Rp "$SERVER_ENV/$item" "$BACKUP_DIR/"
                echo " $item backed up"
            fi
        done
        # The UI keeps writing to the database, and a file copy of a database in
        # use can come out torn. Replace it with a consistent snapshot.
        if [[ -f $SERVER_ENV/$DB ]]; then
            rm -f "$BACKUP_DIR/$DB" "$BACKUP_DIR/$DB"-wal "$BACKUP_DIR/$DB"-shm
            if command -v python3 >/dev/null; then
                python3 -c 'import sqlite3, sys; src, dst = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2]); src.backup(dst); dst.close()' \
                    "$SERVER_ENV/$DB" "$BACKUP_DIR/$DB"
            else
                cp -p "$SERVER_ENV/$DB"* "$BACKUP_DIR/db/"
                echo -e " \033[1;33mpython3 not found: the database was copied as files. Stop the UI first (docker compose stop openvpn-ui) to be sure the copy is consistent.\033[0m"
            fi
        fi
        echo -e "\033[1;32mBackup created at $BACKUP_DIR\033[0m"
        ;;
    -r)
        if command -v docker >/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -qxE 'openvpn|openvpn-ui'; then
            echo -e "\033[1;31mThe service is running. Stop it first: docker compose down\033[0m"; exit 1
        fi
        [[ -e $BACKUP_DIR ]] || { echo -e "\033[1;31mNo backup at $BACKUP_DIR\033[0m"; exit 1; }
        confirm "Replace the environment in \"$SERVER_ENV\" with \"$BACKUP_DIR\"?"
        if [[ -f $BACKUP_DIR ]]; then     # an archive written by the web UI
            tmp=$(mktemp -d)
            trap 'rm -rf "$tmp"' EXIT
            tar xzpf "$BACKUP_DIR" -C "$tmp"
            BACKUP_DIR=$tmp
        fi
        for item in "${ITEMS[@]}"; do
            if [[ $item == db && -e $BACKUP_DIR/db ]]; then
                # Only the database: a write-ahead log left next to a restored database would corrupt it.
                mkdir -p "$SERVER_ENV/db"
                rm -f "$SERVER_ENV/$DB" "$SERVER_ENV/$DB"-wal "$SERVER_ENV/$DB"-shm
                cp -Rp "$BACKUP_DIR/db/." "$SERVER_ENV/db/"
                echo " $item restored"
            elif [[ -e $BACKUP_DIR/$item ]]; then
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
