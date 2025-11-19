# uot (UDP over TLS lanes)

This repository hosts the Go implementation described in `AGENTS.md`. The current milestone provides the executable skeleton plus configuration, logging, metrics, and TLS bootstrap plumbing so future iterations can focus on transport and queueing logic.

## Quick start

```bash
# Prepare TLS material referenced by configs/example.yaml
cp configs/example.yaml /etc/ut/ut.yaml

# Build
export GOMODCACHE=$(pwd)/.gomodcache
export GOCACHE=$(pwd)/.gocache
go build ./cmd/uot

# Run (client or server depending on role value)
./ut -config /etc/ut/ut.yaml

# Optional: embed version metadata
go build -ldflags "-X github.com/fanzy618/uot/internal/version.Version=0.1.0 \
  -X github.com/fanzy618/uot/internal/version.GitCommit=$(git rev-parse HEAD) \
  -X github.com/fanzy618/uot/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/uot
```

- Logs are JSON with level controlled via `UT_LOG_LEVEL` (default `info`) and include a startup line containing build metadata plus a safe configuration snapshot.
- Metrics bind to `metrics.listen_addr` and expose Prometheus data at `metrics.path`.
- M2 baseline: multi-lane TLS fan-out with per-session queues (drop-oldest), metrics-backed backlog tracking, and mTLS-authenticated session reuse on the server.
- Run `make bench` to execute the localhost performance benchmark (reports RTT latency + bandwidth via `BenchmarkLocalhostTunnel`). You can set `tls.disable: true` in a dedicated benchmark config to bypass TLS overhead in trusted environments.

## uot user manual

### Configuration

1. Copy `configs/example.yaml` to your desired location (e.g. `/etc/ut/ut.yaml`) and edit it for each role.
2. Set `role: server` on the EC2 side and `role: client` on the home side. Both must reference the same CA/leaf certificates for mTLS.
3. Adjust listener values as needed:
   - Server: `tcp.listen_addr` defaults to `0.0.0.0:5443`, `udp.wg_udp_addr` should point at the local WireGuard UDP endpoint (often `127.0.0.1:51820`).
   - Client: `tcp.server_addr` is the EC2 hostname/IP plus `:5443`, `udp.listen_addr` is the local port WireGuard peers target (e.g. `127.0.0.1:15000`).
4. Optional knobs include lane count (`tcp.lanes`), queue limits (`queue.max_packets` / `queue.max_bytes`), and Prometheus listener (`metrics.listen_addr`).

### Running

```bash
# build once
make build

# server role on EC2
bin/uot -config /etc/ut/ut-server.yaml

# client role at home
bin/uot -config /etc/ut/ut-client.yaml
```

Key operational behavior:
- Lanes: up to `tcp.lanes` simultaneous TLS connections with `TCP_NODELAY` and 16KiB buffers. The agent auto-dials on first traffic and tears down lanes after `tcp.idle_seconds` (default 120s) without activity.
- UDP limits: packets larger than 64KiB are dropped and logged with `event="pdu_too_large"`.
- Backpressure: when either session queue limit is hit the oldest packet is dropped; metrics report `reason="oldest"`.
- Metrics: visit `http://metrics.listen_addr/metrics` for Prometheus data (`ut_sessions_active`, `ut_udp_*`, `ut_tls_handshake_seconds`, `ut_lane_reconnect_total`, `ut_udp_drop_total`, etc.).
- Logging: JSON via zap, level set by `UT_LOG_LEVEL`. Search for `event=lane_open` or `event=queue_drop_oldest` to diagnose runtime issues.

## Continuous UDP telemetry

`cmd/udpmon` ships a simple reflector + probe pair that continuously measures UDP latency and drop rate between two sites and exports Prometheus metrics for scraping.

```bash
# Build the helper
go build ./cmd/udpmon

# On the far side (EC2, etc.) run a reflector to echo probes
./udpmon -mode reflector -listen :9000

# On the home side run the probe. It sends one packet per second by default
# and exposes metrics/summary logs.
./udpmon -mode probe \
  -listen :0 \
  -target ec2.example.com:9000 \
  -interval 1s \
  -metrics-listen :9501
```

Key metrics: `udpmon_probe_sent_total`, `udpmon_probe_received_total`, `udpmon_probe_dropped_total`, `udpmon_probe_rtt_seconds`, and reflector counters for received/echoed packets. Logs report a rolling summary (`sent/received/dropped + RTT min/avg/max`) every `-log-interval`.

## udpmon user manual

`udpmon` contains two roles:

- `probe`: Dials a reflector, injects one packet per `-interval`, awaits echoes, and records RTT/drops via Prometheus plus periodic zap summaries.
- `reflector`: Listens on a UDP socket, echoes packets back to senders, and exposes simple packet counters.

### Flags (probe mode)

| Flag | Description |
| --- | --- |
| `-listen` | Local UDP address. Use `:0` to bind ephemeral. |
| `-target` | Required. Remote reflector address (`host:port`). |
| `-interval` | Send cadence (default `1s`). |
| `-timeout` | Deadline before considering a probe dropped (default `3s`). |
| `-payload-bytes` | Extra payload after the 16-byte telemetry header (default `32`, max `1400`). |
| `-metrics-listen` | Optional HTTP address (e.g. `:9501`) to expose `/metrics`. |
| `-log-interval` | How often to emit the rolling summary line (default `10s`). |

Example:

```bash
bin/udpmon -mode probe \
  -listen :0 \
  -target reflector.example.com:9000 \
  -interval 500ms \
  -timeout 2s \
  -metrics-listen :9600 \
  -log-interval 30s
```

Summary output includes cumulative sent/received/dropped counts, drop percentage, and RTT min/avg/max.

### Flags (reflector mode)

| Flag | Description |
| --- | --- |
| `-listen` | UDP address to accept probes (default `:0`; set to a public port like `:9000`). |
| `-metrics-listen` | Optional Prometheus endpoint. |

Reflector metrics include `udpmon_reflector_received_total` and `udpmon_reflector_echo_total`, which help confirm incoming traffic even when the probe observes drops.

## Repository layout

```
cmd/uot           # CLI entry point (flag parsing, lifecycle wiring)
cmd/udpmon        # UDP telemetry helper (probe + reflector)
internal/config   # YAML schema, defaults, validation
internal/logging  # zap-based JSON logger helper
internal/metrics  # Prometheus registry + HTTP server
internal/tlsutil  # mTLS helpers for client/server roles
internal/agent    # Client/server runtime (UDP adapters, lanes, TLS piping)
internal/queue    # Drop-oldest FIFO used for per-session backpressure
internal/version  # Build metadata exported to logs
configs           # Example YAML configuration
```

See `AGENTS.md` for the complete product specification, iteration plan, and glossary.
