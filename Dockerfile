# syntax=docker/dockerfile:1
#
# OpenVPN server image.
#
# OpenVPN and easy-rsa are built from the upstream release tarballs (not the
# distro packages) so the image always ships the exact versions pinned below.
# Both tarballs are checksum-pinned; the checksums were taken after verifying
# the upstream OpenPGP signatures (OpenVPN security team key
# F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7, easy-rsa maintainer key
# 6F4056821152F03B6B24F2FCF8489F839D7367F3).

ARG ALPINE_VERSION=3.24.1

# --------------------------------------------------------------------------
# Build stage: compile OpenVPN, unpack easy-rsa
# --------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS build

ARG OPENVPN_VERSION=2.7.7
ARG OPENVPN_SHA256=3ab8f48fd6c26d49ba2333a092433949afdb5c85c0e6a1ff265784fbc04a2463
ARG EASYRSA_VERSION=3.2.6
ARG EASYRSA_SHA256=c2572990ce91112eef8d1b8e4a3b58790da95b68501785c621f69121dfbd22d7

RUN apk add --no-cache build-base linux-headers pkgconf curl \
        openssl-dev lz4-dev lzo-dev libcap-ng-dev libnl3-dev

WORKDIR /build
RUN curl -fsSL -o openvpn.tar.gz \
        "https://github.com/OpenVPN/openvpn/releases/download/v${OPENVPN_VERSION}/openvpn-${OPENVPN_VERSION}.tar.gz" \
    && echo "${OPENVPN_SHA256}  openvpn.tar.gz" | sha256sum -c - \
    && tar xzf openvpn.tar.gz \
    && cd "openvpn-${OPENVPN_VERSION}" \
    && ./configure \
        --prefix=/usr \
        --sysconfdir=/etc/openvpn \
        --enable-dco \
        --disable-plugin-auth-pam \
        --disable-dns-updown-by-default \
    && make -j"$(nproc)" \
    && make DESTDIR=/out install \
    && strip /out/usr/sbin/openvpn

RUN curl -fsSL -o easyrsa.tgz \
        "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz" \
    && echo "${EASYRSA_SHA256}  easyrsa.tgz" | sha256sum -c - \
    && mkdir -p /out/usr/share/easy-rsa \
    && tar xzf easyrsa.tgz --strip-components=1 -C /out/usr/share/easy-rsa --exclude='._*' \
    && chmod 755 /out/usr/share/easy-rsa/easyrsa

# --------------------------------------------------------------------------
# Runtime stage
# --------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION}

ARG OPENVPN_VERSION
ARG EASYRSA_VERSION
LABEL org.opencontainers.image.title="openvpn-server" \
      org.opencontainers.image.description="OpenVPN ${OPENVPN_VERSION} server with easy-rsa ${EASYRSA_VERSION}" \
      org.opencontainers.image.source="https://github.com/dkagramanyan/openvpn-server"

RUN apk --no-cache --no-progress upgrade \
    && apk add --no-cache --no-progress \
        bash openssl lz4-libs lzo libcap-ng libnl3 \
        iptables ip6tables iproute2-minimal \
        oath-toolkit-oathtool libqrencode-tools \
        ca-certificates tzdata

COPY --from=build /out/usr/sbin/openvpn /usr/sbin/openvpn
COPY --from=build /out/usr/lib/openvpn/ /usr/lib/openvpn/
COPY --from=build /out/usr/share/easy-rsa/ /usr/share/easy-rsa/

WORKDIR /opt/app
COPY bin/ /opt/app/bin/
COPY docker-entrypoint.sh /opt/app/docker-entrypoint.sh
RUN chmod 755 /opt/app/bin/* /opt/app/docker-entrypoint.sh \
    && mkdir -p /etc/openvpn /var/log/openvpn /dev/net

ENV OPENVPN_DIR=/etc/openvpn \
    EASYRSA_DIR=/usr/share/easy-rsa

EXPOSE 1195/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD ["/opt/app/bin/healthcheck.sh"]

ENTRYPOINT ["/opt/app/docker-entrypoint.sh"]
