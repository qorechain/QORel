#!/bin/sh
set -e
if ! getent group qorel >/dev/null; then groupadd --system qorel; fi
if ! getent passwd qorel >/dev/null; then
  useradd --system --gid qorel --home-dir /var/lib/qorel --shell /usr/sbin/nologin qorel
fi
