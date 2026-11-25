#!/usr/bin/env bash
# تشغيل على الـ VPS (Ubuntu/Debian) — مرة واحدة
set -euo pipefail

apt-get update
apt-get install -y stunnel4 tinyproxy openssl

mkdir -p /etc/stunnel
openssl req -new -x509 -days 3650 -nodes \
  -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem \
  -subj "/CN=sni-proxy"

cp "$(dirname "$0")/stunnel.conf" /etc/stunnel/stunnel.conf
cp "$(dirname "$0")/tinyproxy.conf" /etc/tinyproxy/tinyproxy.conf

sed -i 's/ENABLED=0/ENABLED=1/' /etc/default/stunnel4 2>/dev/null || true

systemctl enable tinyproxy stunnel4
systemctl restart tinyproxy stunnel4

echo "OK — افتح 443 في الفايروول"
echo "في settings.ini على جهازك:"
echo "  mode = direct"
echo "  host = IP_السيرفر"
