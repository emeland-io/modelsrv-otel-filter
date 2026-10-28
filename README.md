# modelsrv-otel-filter

EmELand **Filter** that selects HTTPS endpoints for certificate probing, writes
OpenTelemetry Collector config for [modelsrv-otel-exporter](../modelsrv-otel-exporter),
merges probe observations onto ApiInstance resources, and authors certificate
Findings when remaining validity is below a configured threshold.

CertManager-covered cluster endpoints stay out of this path. Only ApiInstances
that carry the manual probe annotation are included.

## Well-known annotations

| Key | Role |
|-----|------|
| `emeland.io/certificate.https-endpoint` | Opt-in probe target (absolute `https` URL) |
| `emeland.io/certificate.remaining` | Seconds until expiry (from OTel) |
| `emeland.io/certificate.not-after` | RFC3339 expiry |
| `emeland.io/certificate.issuer` | Certificate issuer |
| `emeland.io/certificate.common-name` | Subject CN |
| `emeland.io/certificate.san` | Comma-separated SANs |
| `emeland.io/certificate.error` | Last probe failure message |
| `emeland.io/certificate.probed-at` | RFC3339 probe time |
| `emeland.io/certificate.source` | `otel` marker on exporter events (stripped before publish) |

## Architecture

```
upstream modelsrv  --ApiInstance-->  modelsrv-otel-filter  --collector.yaml-->  modelsrv-otel-exporter
                                              ^                                         |
                                              |         certificate annotations         |
                                              +-----------------------------------------+
                                              |
                                              +-- Findings --> downstream subscribers
```

1. This filter watches ApiInstance events and collects URLs from
   `emeland.io/certificate.https-endpoint`.
2. It writes a ready-to-run OTel Collector config (`http_check` + `emeland` exporter)
   with `endpoint_mapping` and itself as the exporter's subscriber.
3. `modelsrv-otel-exporter` probes the targets and pushes ApiInstance observation
   events (annotated with `emeland.io/certificate.source=otel`).
4. The filter merges observations onto the upstream snapshot, strips the source
   marker, and raises `CertificateExpiringSoon` / `CertificateExpired` /
   `CertificateProbeFailed` using the same deterministic Finding IDs as
   modelsrv's `endpointprobe` package.

## Usage

```sh
modelsrv-otel-filter \
  --listen 0.0.0.0:8081 \
  --upstream http://modelsrv:8080/api \
  --callback-url http://otel-filter:8081/api \
  --otel-config-out /config/collector.yaml \
  --expiry-threshold 720h

# In another process / sidecar:
modelsrv-otel-exporter --config /config/collector.yaml
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `localhost:8080` | Filter HTTP API bind address |
| `--upstream` | (required) | Upstream modelsrv API base including `/api` |
| `--callback-url` | derived from `--listen` | URL upstream uses to push events |
| `--otel-config-out` | (required) | Path for generated collector YAML |
| `--collection-interval` | `5m` | `http_check` collection interval |
| `--exporter-listen` | `0.0.0.0:24200` | Exporter `listen_addr` in generated config |
| `--expiry-threshold` | `720h` | Finding threshold for remaining validity |
| `--debounce` | `2s` | Debounce before rewriting collector config |
| `--subscribers` | | Comma-separated downstream modelsrv URLs |

## Building

```sh
make ci          # lint, build, test
make run         # requires UPSTREAM and OTEL_CONFIG_OUT
```

## Annotating an ApiInstance

```yaml
kind: ApiInstance
spec:
  displayName: payments-public
  annotations:
    emeland.io/certificate.https-endpoint: https://payments.example.com:443/health
```
