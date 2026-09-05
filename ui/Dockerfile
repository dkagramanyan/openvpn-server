# syntax=docker/dockerfile:1
#
# OpenVPN web UI image. Build context is the repository root:
#   docker build -f ui/Dockerfile .

ARG ALPINE_VERSION=3.24.1
ARG PYTHON_IMAGE=python:3.13-alpine3.24

# --------------------------------------------------------------------------
# easy-rsa (same pinned release as the server image)
# --------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS easyrsa
ARG EASYRSA_VERSION=3.2.6
ARG EASYRSA_SHA256=c2572990ce91112eef8d1b8e4a3b58790da95b68501785c621f69121dfbd22d7
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
    && apk add --no-cache --no-progress bash openssl oath-toolkit-oathtool libqrencode-tools tzdata

COPY --from=easyrsa /out/usr/share/easy-rsa/ /usr/share/easy-rsa/

WORKDIR /opt/openvpn-ui
COPY ui/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt 2>/dev/null \
    || pip install --no-cache-dir -r requirements.txt

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
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header", "--log-level", "info"]
