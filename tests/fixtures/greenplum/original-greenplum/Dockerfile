# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM centos@sha256:dead07b4d8ed7e29e98de0f4504d87e8880d4347859d839686a31da35a3b532f

COPY original-greenplum/centos-vault.repo /etc/yum.repos.d/dfe-centos-vault.repo

RUN yum --disablerepo='*' \
        --enablerepo=c7-extras \
        --assumeyes install epel-release-7-11 \
    && echo "028b9accc59bab1d21f2f3f544df5469910581e728a64fd8c411a725a82300c2  /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7" \
        | sha256sum --check --strict \
    && rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-7 \
    && rpm --query gpg-pubkey-352c64e5-52ae6884 \
    && rm -f /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel-testing.repo \
    && yum clean all \
    && rm -rf /var/cache/yum

RUN curl --fail --location --connect-timeout 15 --max-time 300 \
        --retry 4 --retry-delay 2 \
        --show-error --silent \
        --output /tmp/python2-psutil-5.6.7-1.el7.x86_64.rpm \
        https://archives.fedoraproject.org/pub/archive/epel/7/x86_64/Packages/p/python2-psutil-5.6.7-1.el7.x86_64.rpm \
    && echo "7a87617ec8033a4a2b34f4abd0e1c747507a9ef4d032acadcf2abd1834593390  /tmp/python2-psutil-5.6.7-1.el7.x86_64.rpm" \
        | sha256sum --check --strict \
    && rpmkeys --checksig --verbose /tmp/python2-psutil-5.6.7-1.el7.x86_64.rpm \
        | tee /tmp/python2-psutil-signature.txt \
    && test "$(grep --count --fixed-strings 'Signature, key ID 352c64e5: OK' /tmp/python2-psutil-signature.txt)" = 2 \
    && yum --disablerepo='*' \
        --enablerepo=c7-base,c7-updates,c7-extras \
        --assumeyes install \
        apr-devel-1.4.8-7.el7 \
        bison-3.0.4-2.el7 \
        bzip2-devel-1.0.6-13.el7 \
        flex-2.5.37-6.el7 \
        gcc-4.8.5-44.el7 \
        gcc-c++-4.8.5-44.el7 \
        iproute-4.11.0-30.el7 \
        less-458-10.el7_9 \
        libcurl-devel-7.29.0-59.el7_9.2 \
        libevent-devel-2.0.21-4.el7 \
        libffi-devel-3.0.13-19.el7 \
        libxml2-devel-2.9.1-6.el7_9.6 \
        libyaml-devel-0.1.4-11.el7_0 \
        make-3.82-24.el7 \
        net-tools-2.0-0.25.20131004git.el7 \
        openssh-clients-7.4p1-23.el7_9 \
        openssh-server-7.4p1-23.el7_9 \
        openssl-devel-1.0.2k-26.el7_9 \
        perl-devel-5.16.3-299.el7_9 \
        perl-ExtUtils-Embed-1.30-299.el7_9 \
        procps-ng-3.3.10-28.el7 \
        psmisc-22.20-17.el7 \
        python-devel-2.7.5-94.el7_9 \
        python-lockfile-0.9.1-4.el7.centos \
        python-paramiko-2.1.1-9.el7 \
        PyYAML-3.10-11.el7 \
        readline-devel-6.2-11.el7 \
        rsync-3.1.2-12.el7_9 \
        which-2.20-7.el7 \
        zlib-devel-1.2.7-21.el7_9 \
        /tmp/python2-psutil-5.6.7-1.el7.x86_64.rpm \
    && yum clean all \
    && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
    && rm -rf \
        /var/cache/yum \
        /tmp/python2-psutil-5.6.7-1.el7.x86_64.rpm \
        /tmp/python2-psutil-signature.txt

RUN --mount=type=bind,from=source,source=/,target=/source-artifact,readonly \
    archive=/source-artifact/gpdb-sanitized-62378f1767f22217f7f0474260abfeeb5c2615b9.tar \
    && test "$(stat --format='%s' "${archive}")" = 418805760 \
    && echo "f654c454e0c6a5b8a9d2631888392cee6af5cb68da51d1b5dc773c7e8a4a73af  ${archive}" \
        | sha256sum --check --strict \
    && install --directory /workspace/gpdb \
    && tar --extract --file "${archive}" --directory /workspace/gpdb --strip-components=1 \
    && test ! -e /workspace/gpdb/ci \
    && test ! -e /workspace/gpdb/concourse \
    && test "$(/workspace/gpdb/getversion)" = "4.3.99.00 build dev"

WORKDIR /workspace/gpdb

RUN test "$(./getversion)" = "4.3.99.00 build dev" \
    && ./configure \
        --with-perl \
        --with-python \
        --with-libxml \
        --prefix=/usr/local/gpdb \
    && make -j4 \
    && make install \
    && source /usr/local/gpdb/greenplum_path.sh \
    && python -c 'import gppylib.gphostcache'

RUN make -C contrib/pgcrypto -j4 \
    && make -C contrib/pgcrypto install \
    && test -s /usr/local/gpdb/lib/postgresql/pgcrypto.so \
    && test -s /usr/local/gpdb/share/postgresql/contrib/pgcrypto.sql \
    && test "$(grep --fixed-strings --line-regexp --count \
        'SET search_path = public;' \
        /usr/local/gpdb/share/postgresql/contrib/pgcrypto.sql)" = 1

RUN groupadd --gid 1000 gpadmin \
    && useradd --uid 1000 --gid gpadmin --create-home --shell /bin/bash gpadmin \
    && install --directory --owner=gpadmin --group=gpadmin --mode=0700 /home/gpadmin/.ssh \
    && install --directory --owner=gpadmin --group=gpadmin /home/gpadmin/gpdemo-data \
    && install --directory --mode=0755 /run/sshd \
    && chown -R gpadmin:gpadmin /workspace/gpdb /usr/local/gpdb \
    && rpm -qa --qf '%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\n' \
        > /tmp/dfe-build-rpm-manifest.unsorted \
    && test -s /tmp/dfe-build-rpm-manifest.unsorted \
    && sort /tmp/dfe-build-rpm-manifest.unsorted \
        > /usr/local/gpdb/dfe-build-rpm-manifest.txt \
    && test -s /usr/local/gpdb/dfe-build-rpm-manifest.txt \
    && rm -f /tmp/dfe-build-rpm-manifest.unsorted

COPY original-greenplum/gpadmin-limits.conf /etc/security/limits.d/90-dfe-gpadmin.conf
COPY original-greenplum/entrypoint.sh /usr/local/bin/dfe-original-greenplum-entrypoint
COPY original-greenplum/healthcheck.sh /usr/local/bin/dfe-original-greenplum-healthcheck
COPY original-greenplum/setup-integration.sh /usr/local/bin/dfe-original-greenplum-setup-integration
COPY original-greenplum/verify.sh /usr/local/bin/dfe-original-greenplum-verify

RUN chmod 0644 /etc/security/limits.d/90-dfe-gpadmin.conf \
    && chmod 0755 \
        /usr/local/bin/dfe-original-greenplum-entrypoint \
        /usr/local/bin/dfe-original-greenplum-healthcheck \
        /usr/local/bin/dfe-original-greenplum-setup-integration \
        /usr/local/bin/dfe-original-greenplum-verify

ENV GPHOME=/usr/local/gpdb
ENV PATH=/usr/local/gpdb/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV LD_LIBRARY_PATH=/usr/local/gpdb/lib

ENTRYPOINT ["/usr/local/bin/dfe-original-greenplum-entrypoint"]
