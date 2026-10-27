#!/bin/sh
set -e
install -d -o qorel -g qorel -m 0700 /var/lib/qorel
install -d -m 0755 /etc/qorel
if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
echo "QORel installed. Copy /etc/qorel/config.example.toml to /etc/qorel/config.toml, add keys as user qorel, then: systemctl enable --now qorel"
