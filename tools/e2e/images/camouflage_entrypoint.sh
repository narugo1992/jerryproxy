#!/bin/sh
# Generate a synthetic TLS 1.3 endpoint for the Reality handshake to mirror.
# The certificate is trusted by nothing outside this run and is never a
# recommendation for a production source.
set -eu

SNI="${E2E_REALITY_SNI:-www.example.test}"
PORT="${E2E_PORT:-8443}"

mkdir -p /etc/nginx/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout /etc/nginx/tls/camouflage.key \
  -out /etc/nginx/tls/camouflage.crt \
  -subj "/CN=${SNI}" -addext "subjectAltName=DNS:${SNI}" >/dev/null 2>&1

cat > /etc/nginx/conf.d/default.conf <<CONF
server {
    listen ${PORT} ssl;
    http2 on;
    server_name ${SNI};
    ssl_certificate /etc/nginx/tls/camouflage.crt;
    ssl_certificate_key /etc/nginx/tls/camouflage.key;
    ssl_protocols TLSv1.3;
    location / { return 200 'camouflage'; }
}
CONF

echo "camouflage listening on ${PORT} for ${SNI}" >&2
exec nginx -g 'daemon off;'
