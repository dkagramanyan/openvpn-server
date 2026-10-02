# syntax=docker/dockerfile:1
#
# OpenVPN web UI image. Build context is the repository root:
#   docker build -f ui/Dockerfile .

ARG ALPINE_VERSION=3.24.2
ARG PYTHON_IMAGE=python:3.14-alpine3.24

# --------------------------------------------------------------------------
# easy-rsa (same pinned release as the server image)
# --------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS easyrsa
ARG EASYRSA_VERSION=3.2.7
ARG EASYRSA_SHA256=308743bc9fe871b902d47dbe98d749daff3a05b27531684f02625ce7208d4598
RUN apk add --no-cache curl \
    && curl -fsSL -o /tmp/easyrsa.tgz \
        "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz" \
    && echo "${EASYRSA_SHA256}  /tmp/easyrsa.tgz" | sha256sum -c - \
    && mkdir -p /out/usr/share/easy-rsa \
    && tar xzf /tmp/easyrsa.tgz --strip-components=1 -C /out/usr/share/easy-rsa --exclude='._*' \
    && chmod 755 /out/usr/share/easy-rsa/easyrsa

# --------------------------------------------------------------------------
# Runtime
# --------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}

RUN apk --no-cache --no-progress upgrade \
    && apk add --no-cache --no-progress bash openssl openvpn oath-toolkit-oathtool libqrencode-tools tzdata age

COPY --from=easyrsa /out/usr/share/easy-rsa/ /usr/share/easy-rsa/

WORKDIR /opt/openvpn-ui
COPY ui/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY bin/ /opt/app/bin/
COPY ui/app/ ./app/
RUN chmod 755 /opt/app/bin/*

ENV OPENVPN_DIR=/etc/openvpn \
    EASYRSA_DIR=/usr/share/easy-rsa \
    OVPN_BIN_DIR=/opt/app/bin \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import os,sys,urllib.request as u; h=os.environ['UVICORN_HOST']; h='127.0.0.1' if h=='0.0.0.0' else h; sys.exit(u.build_opener(u.ProxyHandler({})).open(f'http://{h}:8080/healthz', timeout=4).status != 200)"]

# UVICORN_HOST sets the listen address; X-Forwarded-For is only believed from
# FORWARDED_ALLOW_IPS (a reverse proxy), never from arbitrary clients.
ENV UVICORN_HOST=0.0.0.0 FORWARDED_ALLOW_IPS=127.0.0.1
CMD ["python", "-m", "uvicorn", "app.main:app", "--port", "8080", "--proxy-headers", "--no-server-header"]
