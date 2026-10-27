# Installing QORel

QORel is one binary, `qorel`. Every release is published on
[GitHub Releases](https://github.com/qorechain/QORel/releases) with:

- a `SHA256SUMS` file;
- build provenance attestations (`gh attestation verify <file> --repo qorechain/QORel`).

| Platform | Channel |
|---|---|
| Linux x86_64 / arm64 (glibc 2.28+: Ubuntu 20.04+, Debian 11+, RHEL / Rocky / Alma 8+, Amazon Linux 2023) | tarball, `.deb`, `.rpm`, container, Homebrew |
| macOS Apple Silicon / Intel | tarball, Homebrew |
| Anything with Docker / Kubernetes | `ghcr.io/qorechain/qorel` |
| From source | `cargo install --git` |

Windows is not supported (upstream Hermes releases do not include it either); use the container under WSL2.

## Release tarball

```bash
V=0.1.0
T=x86_64-unknown-linux-gnu   # or aarch64-unknown-linux-gnu, aarch64-apple-darwin, x86_64-apple-darwin
curl -LO https://github.com/qorechain/QORel/releases/download/v$V/qorel-v$V-$T.tar.gz
curl -LO https://github.com/qorechain/QORel/releases/download/v$V/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS   # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
tar -xzf qorel-v$V-$T.tar.gz
sudo install -m 0755 qorel-v$V-$T/qorel /usr/local/bin/qorel
qorel --version
```

## Debian / Ubuntu (.deb) and RHEL family (.rpm)

```bash
sudo apt install ./qorel_${V}_amd64.deb       # or arm64
sudo dnf install ./qorel-${V}-1.x86_64.rpm    # or aarch64
```

What the packages install:

- `/usr/bin/qorel`
- a hardened `qorel.service`, running as user `qorel` with its home in `/var/lib/qorel`
- `/etc/qorel/config.example.toml`

Then:

```bash
sudo cp /etc/qorel/config.example.toml /etc/qorel/config.toml   # edit it
sudo -u qorel qorel --config /etc/qorel/config.toml keys add --chain <chain> --key-name relayer --mnemonic-file <file>
sudo -u qorel qorel --config /etc/qorel/config.toml keys register-pqc --chain <qorechain id>   # QoreChain only, once
sudo -u qorel qorel --config /etc/qorel/config.toml health-check
sudo systemctl enable --now qorel
```

Delete the mnemonic file after `keys add`. Key files are written owner-only (0600).

## Homebrew (macOS and Linux)

```bash
brew install qorechain/tap/qorel
```

## Container

```bash
docker run --rm ghcr.io/qorechain/qorel:0.1.0 --version
docker run -d --name qorel --restart unless-stopped \
  -v $HOME/.qorel:/home/nonroot/.hermes \
  ghcr.io/qorechain/qorel:0.1.0 start
```

- **Image:** multi-arch (amd64 / arm64), distroless and non-root, signed with cosign keyless signing. To verify:

  ```bash
  cosign verify ghcr.io/qorechain/qorel:0.1.0 \
    --certificate-identity-regexp 'https://github.com/qorechain/QORel/.github/workflows/qorel-release.yml@refs/tags/v.*' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

- **Mounts:** the config (`config.toml`) and the `keys/` folder are read from the mounted directory.

## From source

```bash
cargo install --locked --git https://github.com/qorechain/QORel --tag v0.1.0 ibc-relayer-cli --bin qorel
```

This needs Rust 1.85, `protoc` and `clang`; on Linux it also needs the OpenSSL headers. Add `--features vendored-openssl` to compile OpenSSL in instead.

## Next steps

- [OPERATORS.md](OPERATORS.md): configuration, keys, gas, safety checks.
- [VALIDATOR.md](VALIDATOR.md): running QORel next to a validator.
- [SIGNER.md](SIGNER.md) and [SIGNING_FROM_ANY_LANGUAGE.md](SIGNING_FROM_ANY_LANGUAGE.md): the post-quantum signer and how to reproduce it in other languages.
