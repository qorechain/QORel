#!/bin/bash
# Builds the qorel Linux release binary inside a manylinux_2_28 container
# (glibc 2.28 baseline, OpenSSL compiled in). Used by CI and for local checks.
#   packaging/build-linux.sh <out-dir>
set -euo pipefail
OUT="${1:-dist}"
PROTOC_VERSION=29.3

# openssl-devel: build-time tools (proc macros) link the system OpenSSL; the
# qorel binary itself gets OpenSSL compiled in (vendored-openssl).
dnf install -y -q clang clang-devel perl-IPC-Cmd perl-Time-Piece unzip openssl-devel >/dev/null

case "$(uname -m)" in
  x86_64) PROTOC_ARCH=x86_64 ;;
  aarch64) PROTOC_ARCH=aarch_64 ;;
  *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
esac
curl -sSfL -o /tmp/protoc.zip \
  "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-${PROTOC_ARCH}.zip"
unzip -q -o /tmp/protoc.zip -d /usr/local

if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y -q --default-toolchain 1.85.0 --profile minimal >/dev/null
fi
. "$HOME/.cargo/env"

git config --global --add safe.directory "$PWD"
QOREL_RELEASE=1 cargo build --release --locked -p ibc-relayer-cli --bin qorel --features vendored-openssl
mkdir -p "$OUT"
cp "${CARGO_TARGET_DIR:-target}/release/qorel" "$OUT/qorel"
"$OUT/qorel" --version
if ldd "$OUT/qorel" | grep -E 'libssl|libcrypto'; then
  echo "qorel links the system OpenSSL; expected it compiled in" >&2
  exit 1
fi
