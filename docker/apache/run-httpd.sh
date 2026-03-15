#!/bin/sh
set -eu

CERT_DIR="/usr/local/apache2/conf/certs"
mkdir -p "${CERT_DIR}"

if [ ! -s "${CERT_DIR}/server.crt" ] || [ ! -s "${CERT_DIR}/server.key" ]; then
  openssl req \
    -x509 \
    -nodes \
    -newkey rsa:2048 \
    -keyout "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -days 3650 \
    -subj "/C=KR/ST=Seoul/L=Seoul/O=EASM/CN=easm-web"
fi

httpd-foreground
