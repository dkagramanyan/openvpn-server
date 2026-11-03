#!/bin/bash
# Backup / restore the OpenVPN server environment (PKI, profiles, configs, UI database).
#
# The web UI also writes an archive of the same files once a day into
# <server dir>/backups; -r restores from such an archive as well, also from an
# encrypted one (.tar.gz.age) when given the private key with -i.
set -euo pipefail

usage() {
    echo -e "\n\033[1mBackup or restore of the OpenVPN server environment\033[0m"
    echo -e "  \033[1;32mBackup:\033[0m  sudo ./backup.sh [-y] -b <server dir> <backup dir>"
    echo -e "  \033[1;34mRestore:\033[0m sudo ./backup.sh [-y] [-i <key file>] -r <server dir> <backup dir | backup archive>\n"
    echo -e "  -y  do not ask for confirmation (for cron)"
    echo -e "  -i  the age private key that opens an encrypted archive (.tar.gz.age)"
    echo -e "  Example: sudo ./backup.sh -b ~/openvpn-server ~/backup/openvpn-$(date +%F)\n"
    exit 1
}

YES=0
IDENTITY=
if [[ ${1:-} == -y ]]; then YES=1; shift; fi
if [[ ${1:-} == -i ]]; then IDENTITY=${2:-}; shift 2 || usage; fi
[[ $# -eq 3 ]] || usage
ACTION=$1
SERVER_ENV=${2%/}
BACKUP_DIR=${3%/}

ITEMS=(server.conf config pki clients staticclients guests fw-rules.sh docker-compose.yml .env)
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
        mkdir -p "$BACKUP_DIR/db"
        if command -v docker >/dev/null && docker inspect openvpn-ui >/dev/null 2>&1; then
            docker exec openvpn-ui python -m app.migrate_db dump --stdout > "$BACKUP_DIR/db/openvpn-ui.pgdump"
        elif command -v python3 >/dev/null; then
            python3 -m app.migrate_db dump --output "$BACKUP_DIR/db/openvpn-ui.pgdump"
        else
            echo "PostgreSQL backup needs the running UI container or its Python/client tools" >&2
            exit 1
        fi
        chmod 600 "$BACKUP_DIR/db/openvpn-ui.pgdump"
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
            if [[ $BACKUP_DIR == *.age ]]; then
                [[ -f $IDENTITY ]] || { echo -e "\033[1;31mThis archive is encrypted: pass the private key with -i <key file>\033[0m"; exit 1; }
                command -v age >/dev/null || { echo -e "\033[1;31mage is not installed. Install it, or decrypt on another machine: age -d -i <key file> archive.tar.gz.age > archive.tar.gz\033[0m"; exit 1; }
                age -d -i "$IDENTITY" "$BACKUP_DIR" | tar xzpf - -C "$tmp"
            else
                tar xzpf "$BACKUP_DIR" -C "$tmp"
            fi
            BACKUP_DIR=$tmp
        fi
        for item in "${ITEMS[@]}" db; do
            if [[ $item == docker-compose.yml && -f $BACKUP_DIR/db/openvpn-ui.db && -f $SERVER_ENV/$item ]] \
                && grep -q '^  postgres:' "$SERVER_ENV/$item" && ! grep -q '^  postgres:' "$BACKUP_DIR/$item"; then
                # An older archive must not replace the current migration services.
                mkdir -p "$SERVER_ENV/db"
                cp -p "$BACKUP_DIR/$item" "$SERVER_ENV/db/legacy-docker-compose.yml"
                echo " current PostgreSQL Compose kept; old Compose saved in db/legacy-docker-compose.yml"
            elif [[ $item == db && -e $BACKUP_DIR/db ]]; then
                # Only the database: a write-ahead log left next to a restored database would corrupt it.
                mkdir -p "$SERVER_ENV/db"
                rm -f "$SERVER_ENV/$DB" "$SERVER_ENV/$DB"-wal "$SERVER_ENV/$DB"-shm "$SERVER_ENV/db/openvpn-ui.pgdump"
                cp -Rp "$BACKUP_DIR/db/." "$SERVER_ENV/db/"
                echo " $item restored"
            elif [[ -e $BACKUP_DIR/$item ]]; then
                rm -rf "${SERVER_ENV:?}/$item"
                cp -Rp "$BACKUP_DIR/$item" "$SERVER_ENV/"
                echo " $item restored"
            fi
        done
        echo -e "\033[1;34mFiles restored. Run the PostgreSQL import with bin/upgrade-relay.sh before starting the UI\033[0m"
        ;;
    *)
        usage
        ;;
esac
