# QORel container image, built from the release binaries (no compilation here).
#   dist/linux-amd64/qorel and dist/linux-arm64/qorel must exist.
# Mount the config and keys at /home/nonroot/.hermes (or pass --config).
FROM gcr.io/distroless/cc-debian12:nonroot
ARG TARGETARCH
LABEL org.opencontainers.image.title="QORel" \
      org.opencontainers.image.description="IBC relayer for QoreChain and any Cosmos SDK chain, with post-quantum hybrid signing" \
      org.opencontainers.image.source="https://github.com/qorechain/QORel" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="QoreChain"
COPY --chmod=0755 dist/linux-${TARGETARCH}/qorel /usr/bin/qorel
USER nonroot
ENTRYPOINT ["/usr/bin/qorel"]
CMD ["--help"]
