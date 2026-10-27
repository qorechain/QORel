#!/bin/bash
# Prints the Homebrew formula for a published QORel release, using the
# release's SHA256SUMS. Commit the output as Formula/qorel.rb in
# qorechain/homebrew-tap.
#   packaging/homebrew-formula.sh 0.1.0 > Formula/qorel.rb
set -euo pipefail
V="$1"
BASE="https://github.com/qorechain/QORel/releases/download/v${V}"
SUMS="$(curl -sSfL "${BASE}/SHA256SUMS")"
sha() { echo "$SUMS" | awk -v f="qorel-v${V}-$1.tar.gz" '$2 == f { print $1 }'; }

for t in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu; do
  [ -n "$(sha "$t")" ] || { echo "no checksum for $t in SHA256SUMS" >&2; exit 1; }
done

cat <<EOF
class Qorel < Formula
  desc "IBC relayer for QoreChain and any Cosmos SDK chain, with post-quantum hybrid signing"
  homepage "https://github.com/qorechain/QORel"
  version "${V}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "${BASE}/qorel-v${V}-aarch64-apple-darwin.tar.gz"
      sha256 "$(sha aarch64-apple-darwin)"
    end
    on_intel do
      url "${BASE}/qorel-v${V}-x86_64-apple-darwin.tar.gz"
      sha256 "$(sha x86_64-apple-darwin)"
    end
  end

  on_linux do
    on_arm do
      url "${BASE}/qorel-v${V}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha aarch64-unknown-linux-gnu)"
    end
    on_intel do
      url "${BASE}/qorel-v${V}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha x86_64-unknown-linux-gnu)"
    end
  end

  def install
    bin.install "qorel"
    pkgshare.install "config.example.toml"
    doc.install "README.md", "NOTICE"
  end

  test do
    assert_match "qorel #{version}", shell_output("#{bin}/qorel --version")
  end
end
EOF
