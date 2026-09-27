#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || -z "$1" ]]; then
    echo "usage: generate.sh OUTPUT_DIRECTORY" >&2
    exit 2
fi

output_directory="$1"
ca_certificate="${output_directory}/fixture-ca.pem"
server_certificate="${output_directory}/server.pem"
server_key="${output_directory}/server-key.pem"
wrong_ca_certificate="${output_directory}/wrong-ca.pem"
fingerprints_file="${output_directory}/certificate-fingerprints.txt"

mkdir -p -- "${output_directory}"

existing_material_is_valid() {
    [[ -s "${ca_certificate}" \
        && -s "${server_certificate}" \
        && -s "${server_key}" \
        && -s "${wrong_ca_certificate}" \
        && -s "${fingerprints_file}" ]] \
        || return 1
    openssl x509 -checkend 604800 -noout -in "${ca_certificate}" >/dev/null \
        || return 1
    openssl x509 -checkend 604800 -noout -in "${server_certificate}" >/dev/null \
        || return 1
    openssl x509 -checkend 604800 -noout -in "${wrong_ca_certificate}" >/dev/null \
        || return 1
    openssl pkey -check -noout -in "${server_key}" >/dev/null \
        || return 1
    cmp \
        <(openssl pkey -pubout -in "${server_key}") \
        <(openssl x509 -pubkey -noout -in "${server_certificate}") \
        >/dev/null \
        || return 1
    openssl verify \
        -purpose sslserver \
        -verify_hostname localhost \
        -CAfile "${ca_certificate}" \
        "${server_certificate}" \
        >/dev/null \
        || return 1
    openssl verify \
        -purpose sslserver \
        -verify_ip 127.0.0.1 \
        -CAfile "${ca_certificate}" \
        "${server_certificate}" \
        >/dev/null \
        || return 1
    openssl verify \
        -purpose sslserver \
        -verify_hostname forensic-data-phase05-clickhouse \
        -CAfile "${ca_certificate}" \
        "${server_certificate}" \
        >/dev/null \
        || return 1
    if openssl verify \
        -purpose sslserver \
        -CAfile "${wrong_ca_certificate}" \
        "${server_certificate}" \
        >/dev/null 2>&1; then
        return 1
    fi
}

if existing_material_is_valid; then
    exit 0
fi

work_directory="$(mktemp -d)"
cleanup() {
    rm -f -- \
        "${work_directory}/fixture-ca-key.pem" \
        "${work_directory}/fixture-ca.pem" \
        "${work_directory}/fixture-ca.srl" \
        "${work_directory}/server-key.pem" \
        "${work_directory}/server.csr" \
        "${work_directory}/server.pem" \
        "${work_directory}/wrong-ca-key.pem" \
        "${work_directory}/wrong-ca.pem" \
        "${work_directory}/certificate-fingerprints.txt"
    rmdir -- "${work_directory}"
}
trap cleanup EXIT

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 3650 \
    -subj "/CN=DFE ClickHouse fixture CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${work_directory}/fixture-ca-key.pem" \
    -out "${work_directory}/fixture-ca.pem" \
    >/dev/null 2>&1

openssl req \
    -new \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -subj "/CN=forensic-data-phase05-clickhouse" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:localhost,DNS:clickhouse,DNS:forensic-data-phase05-clickhouse,IP:127.0.0.1" \
    -keyout "${work_directory}/server-key.pem" \
    -out "${work_directory}/server.csr" \
    >/dev/null 2>&1

openssl x509 \
    -req \
    -sha256 \
    -days 3650 \
    -copy_extensions copy \
    -in "${work_directory}/server.csr" \
    -CA "${work_directory}/fixture-ca.pem" \
    -CAkey "${work_directory}/fixture-ca-key.pem" \
    -CAcreateserial \
    -out "${work_directory}/server.pem" \
    >/dev/null 2>&1

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 3650 \
    -subj "/CN=DFE unrelated fixture CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "${work_directory}/wrong-ca-key.pem" \
    -out "${work_directory}/wrong-ca.pem" \
    >/dev/null 2>&1

openssl verify \
    -purpose sslserver \
    -verify_hostname localhost \
    -CAfile "${work_directory}/fixture-ca.pem" \
    "${work_directory}/server.pem" \
    >/dev/null
openssl verify \
    -purpose sslserver \
    -verify_ip 127.0.0.1 \
    -CAfile "${work_directory}/fixture-ca.pem" \
    "${work_directory}/server.pem" \
    >/dev/null
if openssl verify \
    -purpose sslserver \
    -CAfile "${work_directory}/wrong-ca.pem" \
    "${work_directory}/server.pem" \
    >/dev/null 2>&1; then
    echo "unrelated fixture CA unexpectedly verified the server certificate" >&2
    exit 1
fi

{
    printf "fixture_ca_"
    openssl x509 -sha256 -fingerprint -noout -in "${work_directory}/fixture-ca.pem"
    printf "server_"
    openssl x509 -sha256 -fingerprint -noout -in "${work_directory}/server.pem"
    printf "wrong_ca_"
    openssl x509 -sha256 -fingerprint -noout -in "${work_directory}/wrong-ca.pem"
} >"${work_directory}/certificate-fingerprints.txt"

install -o 101 -g 101 -m 0444 \
    "${work_directory}/fixture-ca.pem" \
    "${ca_certificate}"
install -o 101 -g 101 -m 0444 \
    "${work_directory}/server.pem" \
    "${server_certificate}"
install -o 101 -g 101 -m 0400 \
    "${work_directory}/server-key.pem" \
    "${server_key}"
install -o 101 -g 101 -m 0444 \
    "${work_directory}/wrong-ca.pem" \
    "${wrong_ca_certificate}"
install -o 101 -g 101 -m 0444 \
    "${work_directory}/certificate-fingerprints.txt" \
    "${fingerprints_file}"
