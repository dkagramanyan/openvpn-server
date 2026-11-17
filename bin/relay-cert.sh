#!/bin/sh
# relay-cert.sh: the Apple relay's certificate, from Let's Encrypt with a DNS-01
# challenge at the DNS provider (the same service account the gateway's Traefik
# uses), renewed when due. Runs in the relay-cert container (lego's image).
#
#   relay-cert.sh   check twice a day; get or renew the certificate
#   As lego's deploy hook (LEGO_HOOK_CERT_PATH set): keep the new files.
#
# lego keeps its account and certificates in /data (config/acme/). The files
# the relay reads are /tls/fullchain.pem and /tls/privkey.pem, owned by the
# relay's user (65532); the relay loads a renewed pair within 30 s by itself.
set -u
DATA=/data
TLS=/tls
CURRENT=$DATA/current

LEGO=${LEGO:-/lego}        # the image keeps it at /, not on PATH

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [relay-cert] $*"; }

# Copy the kept pair to /tls when it differs (also after relay-tls/ was emptied).
publish() {
    [ -s "$CURRENT/fullchain.pem" ] && [ -s "$CURRENT/privkey.pem" ] || return 0
    # Devices need the issuer next to the certificate: never hand over a bare one.
    if [ "$(grep -c 'BEGIN CERTIFICATE' "$CURRENT/fullchain.pem")" -lt 2 ]; then
        log "the new certificate has no issuer chain; the relay keeps the one it has"
        return 1
    fi
    cmp -s "$CURRENT/fullchain.pem" "$TLS/fullchain.pem" && cmp -s "$CURRENT/privkey.pem" "$TLS/privkey.pem" && return 0
    for f in privkey.pem fullchain.pem; do
        cp "$CURRENT/$f" "$TLS/.$f.new" && chown 65532:65532 "$TLS/.$f.new" && chmod 0600 "$TLS/.$f.new" &&
            mv -f "$TLS/.$f.new" "$TLS/$f" || { log "cannot write $TLS/$f"; return 1; }
    done
    log "certificate for $DOMAIN handed to the relay"
}

if [ -n "${LEGO_HOOK_CERT_PATH:-}" ]; then
    DOMAIN=${DOMAIN:-${LEGO_HOOK_CERT_DOMAINS:-}}
    # lego v5 names the new files in LEGO_HOOK_CERT_PATH (with the issuer: a full chain) and LEGO_HOOK_CERT_KEY_PATH.
    mkdir -p "$CURRENT" && chmod 0700 "$CURRENT"
    cp "$LEGO_HOOK_CERT_PATH" "$CURRENT/fullchain.pem.new" && cp "$LEGO_HOOK_CERT_KEY_PATH" "$CURRENT/privkey.pem.new" &&
        mv -f "$CURRENT/privkey.pem.new" "$CURRENT/privkey.pem" && mv -f "$CURRENT/fullchain.pem.new" "$CURRENT/fullchain.pem" ||
        { log "cannot keep the new certificate"; exit 1; }
    publish
    exit
fi

DOMAIN=${RELAY_CERT_DOMAIN:-}
if [ -z "$DOMAIN" ] || [ -z "${ACME_EMAIL:-}" ]; then
    log "off: set RELAY_CERT_DOMAIN (the relay's hostname) and ACME_EMAIL in .env, plus the DNS provider's credentials"
    exec sleep 2147483647
fi
export DOMAIN
provider=${ACME_DNS_PROVIDER:-selectelv2}
# Let's Encrypt checks the TXT record from several places at once, some through
# resolvers that still hold the name's previous answer (left-over challenge
# records, TTL 60 s at Selectel): wait longer than that before it looks.
log "certificate for $DOMAIN from ${ACME_CA_SERVER:-Let's Encrypt}, DNS challenge at $provider"
while :; do
    publish
    # lego run gets the certificate the first time and renews it when due (a third of its
    # lifetime left, or as the CA's renewal info says); otherwise it changes nothing.
    if "$LEGO" run --path "$DATA" --log.format text --accept-tos --email "$ACME_EMAIL" --domains "$DOMAIN" \
            --dns "$provider" ${ACME_DNS_RESOLVERS:+--dns.resolvers "$ACME_DNS_RESOLVERS"} \
            --dns.propagation.wait "${ACME_DNS_WAIT:-120s}" \
            ${ACME_CA_SERVER:+--server "$ACME_CA_SERVER"} \
            --deploy-hook /app/relay-cert.sh; then
        publish
        sleep 43200
    else
        log "could not get or renew the certificate; trying again in an hour"
        sleep 3600
    fi
done
