# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM ubuntu@sha256:281c5745f657873d78e5531fc5ba8575f46ab7769b94550ac99543f122679986

ENV DEBIAN_FRONTEND=noninteractive

COPY greengage/ubuntu-snapshot.list /etc/apt/sources.list

RUN --mount=type=bind,from=artifacts,source=/,target=/artifacts,readonly \
    set -eu; \
    package=/artifacts/greengage7_7.5.0.ubuntu22.04_amd64.deb; \
    ca_certificates=/artifacts/ca-certificates_20260601~22.04.1_all.deb; \
    test "$(stat --format='%s' "${package}")" = 25807136; \
    echo "2ca71f84f4fbb6175de77e193f4b1fa5732f0439f2e6f7458cb7b4cade34d0a0  ${package}" \
        | sha256sum --check --strict; \
    test "$(dpkg-deb --field "${package}" Package)" = greengage7; \
    test "$(dpkg-deb --field "${package}" Version)" = 7.5.0; \
    test "$(dpkg-deb --field "${package}" Architecture)" = amd64; \
    test "$(stat --format='%s' "${ca_certificates}")" = 140666; \
    echo "6e8cdcc8c86103acd4fc14649eac62ff2037108389074a7b167567af33c32245  ${ca_certificates}" \
        | sha256sum --check --strict; \
    test "$(dpkg-deb --field "${ca_certificates}" Package)" = ca-certificates; \
    test "$(dpkg-deb --field "${ca_certificates}" Version)" = '20260601~22.04.1'; \
    test "$(dpkg-deb --field "${ca_certificates}" Architecture)" = all; \
    echo "1a4dd63e5c76728960a2edddae22e2e0fc53df8e8b87806deb971030ac704eb0  /usr/share/keyrings/ubuntu-archive-keyring.gpg" \
        | sha256sum --check --strict; \
    install --directory /tmp/dfe-ca-bootstrap; \
    dpkg-deb --extract "${ca_certificates}" /tmp/dfe-ca-bootstrap; \
    find /tmp/dfe-ca-bootstrap/usr/share/ca-certificates \
        -type f -name '*.crt' -exec cat {} + > /tmp/dfe-ca-bootstrap.pem; \
    test -s /tmp/dfe-ca-bootstrap.pem; \
    rm -f /etc/apt/sources.list.d/*; \
    rm -rf /var/lib/apt/lists/*; \
    test "$(grep -Evc '^(#|$)' /etc/apt/sources.list)" = 3; \
    test "$(grep -Ec '^deb \[check-valid-until=no signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg\] https://snapshot\.ubuntu\.com/ubuntu/20260924T000000Z/ jammy(-updates|-security)? main restricted universe multiverse$' /etc/apt/sources.list)" = 3; \
    apt-get \
        --option Acquire::https::CAInfo=/tmp/dfe-ca-bootstrap.pem \
        --option Acquire::https::Timeout=30 \
        --option Acquire::Retries=4 \
        --option APT::Update::Error-Mode=any \
        update; \
    test "$(apt-get indextargets --format '$(SITE)' | sort --unique)" = 'https://snapshot.ubuntu.com/ubuntu/20260924T000000Z'; \
    apt-cache policy ca-certificates locales openssl; \
    test "$(apt-cache policy ca-certificates | awk '/Candidate:/ { print $2 }')" = '20260601~22.04.1'; \
    apt-get \
        --option Acquire::https::CAInfo=/tmp/dfe-ca-bootstrap.pem \
        --option Acquire::https::Timeout=30 \
        --option Acquire::Retries=4 \
        install --yes --no-install-recommends \
        ca-certificates=20260601~22.04.1 locales "${package}"; \
    test "$(dpkg-query --show --showformat='${Version}' ca-certificates)" = '20260601~22.04.1'; \
    test -s /etc/ssl/certs/ca-certificates.crt; \
    rm -rf /tmp/dfe-ca-bootstrap /tmp/dfe-ca-bootstrap.pem /var/lib/apt/lists/*; \
    apt-get \
        --option Acquire::https::Timeout=30 \
        --option Acquire::Retries=4 \
        --option APT::Update::Error-Mode=any \
        update; \
    test "$(apt-get indextargets --format '$(SITE)' | sort --unique)" = 'https://snapshot.ubuntu.com/ubuntu/20260924T000000Z'; \
    locale-gen en_US.UTF-8; \
    test "$(dpkg-query --show --showformat='${Version}' greengage7)" = 7.5.0; \
    dpkg-query --show --showformat='${binary:Package}|${Version}|${Architecture}\n' \
        > /tmp/dfe-build-dpkg-manifest.unsorted; \
    test -s /tmp/dfe-build-dpkg-manifest.unsorted; \
    sort /tmp/dfe-build-dpkg-manifest.unsorted \
        > /opt/greengagedb/greengage7/dfe-build-dpkg-manifest.txt; \
    test -s /opt/greengagedb/greengage7/dfe-build-dpkg-manifest.txt; \
    rm -f /tmp/dfe-build-dpkg-manifest.unsorted; \
    rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub; \
    rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 1000 gpadmin \
    && useradd --uid 1000 --gid gpadmin --create-home --shell /bin/bash gpadmin \
    && install --directory --owner=gpadmin --group=gpadmin --mode=0700 /home/gpadmin/.ssh \
    && install --directory --owner=gpadmin --group=gpadmin /data \
    && install --directory --mode=0755 /run/sshd \
    && chown -R gpadmin:gpadmin /opt/greengagedb/greengage7

COPY greengage/gpadmin-limits.conf /etc/security/limits.d/90-dfe-gpadmin.conf
COPY --chown=gpadmin:gpadmin greengage/gpinitsystem_config /home/gpadmin/gpinitsystem_config
COPY greengage/entrypoint.sh /usr/local/bin/dfe-greengage-entrypoint
COPY greengage/healthcheck.sh /usr/local/bin/dfe-greengage-healthcheck
COPY greengage/verify.sh /usr/local/bin/dfe-greengage-verify

RUN chmod 0644 \
        /etc/security/limits.d/90-dfe-gpadmin.conf \
        /home/gpadmin/gpinitsystem_config \
    && chmod 0755 \
        /usr/local/bin/dfe-greengage-entrypoint \
        /usr/local/bin/dfe-greengage-healthcheck \
        /usr/local/bin/dfe-greengage-verify

ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8
ENV GPHOME=/opt/greengagedb/greengage7
ENV PATH=/opt/greengagedb/greengage7/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH=/opt/greengagedb/greengage7/lib

ENTRYPOINT ["/usr/local/bin/dfe-greengage-entrypoint"]
