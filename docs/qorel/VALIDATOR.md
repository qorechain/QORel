# Running QORel next to a validator

Validators often relay the channels of their own chain. QORel can run on the validator host, as a sidecar container, or in Kubernetes. Each mode below keeps the relayer isolated from the validator's own keys.

## Ground rules

- **Use a dedicated relayer account.** Never the validator operator key and never the consensus key. Fund it with what the relayer needs for fees.
- **One relayer process per relayer key.** Two processes signing with the same key fight over account sequences.
- **Relay only your channels.** Set a `packet_filter`.
- **Point QORel at the local node.** Use `http://127.0.0.1:26657`, `:9090` and `ws://127.0.0.1:26657/websocket`, and keep those ports closed to the internet.
- **On QoreChain**, register the relayer's post-quantum key once with `qorel keys register-pqc`, and check `qorel keys pqc-status` before starting.

## 1. systemd on the validator host

1. Install the `.deb` or `.rpm` package (see [INSTALL.md](INSTALL.md)). It creates:
   - a `qorel` system user, separate from the validator's user;
   - a hardened `qorel.service`.
2. Edit `/etc/qorel/config.toml` with the local node endpoints.
3. Add the relayer key as user `qorel`.
4. Run `systemctl enable --now qorel`.
5. Give QORel lower priority than the node, so it never competes with block production:

   ```ini
   # /etc/systemd/system/qorel.service.d/priority.conf
   [Service]
   Nice=10
   CPUWeight=20
   MemoryMax=1G
   ```

## 2. Docker Compose sidecar

```yaml
services:
  qorel:
    image: ghcr.io/qorechain/qorel:0.1.0
    command: ["--config", "/home/nonroot/.hermes/config.toml", "start"]
    network_mode: host          # reach the node on 127.0.0.1
    restart: unless-stopped
    volumes:
      - ./qorel:/home/nonroot/.hermes   # config.toml + keys/ (owner uid 65532, mode 0700)
    deploy:
      resources:
        limits: { cpus: "1.0", memory: 1g }
```

## 3. Kubernetes

Keep the mnemonic in your secret store and rebuild the keys at start:
1. An init container runs `qorel keys add` (and `register-pqc` once, by hand) into an `emptyDir` with `medium: Memory`.
2. The main container runs `qorel start` on the same volume.

That way the keys exist only in memory.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: qorel }
spec:
  replicas: 1                      # never more than one per key
  strategy: { type: Recreate }
  selector: { matchLabels: { app: qorel } }
  template:
    metadata: { labels: { app: qorel } }
    spec:
      securityContext: { runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532 }
      volumes:
        - name: home
          emptyDir: { medium: Memory }
        - name: config
          configMap: { name: qorel-config }
        - name: mnemonic
          secret: { secretName: qorel-relayer-mnemonic }   # key: mnemonic
      initContainers:
        - name: keys
          image: ghcr.io/qorechain/qorel:0.1.0
          args: ["--config", "/config/config.toml", "keys", "add", "--chain", "qorechain-vladi",
                 "--key-name", "relayer", "--mnemonic-file", "/secret/mnemonic", "--overwrite"]
          volumeMounts:
            - { name: home, mountPath: /home/nonroot/.hermes }
            - { name: config, mountPath: /config }
            - { name: mnemonic, mountPath: /secret, readOnly: true }
        # repeat the init container for each chain in the config
      containers:
        - name: qorel
          image: ghcr.io/qorechain/qorel:0.1.0
          args: ["--config", "/config/config.toml", "start"]
          ports: [{ containerPort: 3001, name: telemetry }]
          resources: { limits: { cpu: "1", memory: 1Gi } }
          volumeMounts:
            - { name: home, mountPath: /home/nonroot/.hermes }
            - { name: config, mountPath: /config }
```

The config's `key_store_folder` must point at `/home/nonroot/.hermes/keys` (or leave it unset).

## Monitoring

Enable `[telemetry]` (Prometheus format on port 3001) and alert on:

| What | Where |
|---|---|
| Process up | the telemetry endpoint answers |
| Pending packets / acks on your channels | `qorel query packet pending` |
| Relayer balances on each chain | balance queries |
| Post-quantum key ready | `qorel keys pqc-status` reports `ready_to_relay: true` |
| Client freshness | `qorel` refreshes clients at 1/3 of the trusting period; alert if a client has not been updated for about half of it |
