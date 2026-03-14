# Gateweb

**Open-source Secure Web Gateway (SWG) in a single Go binary.**

Gateweb is an HTTP/HTTPS forward proxy that enforces access policies, categorizes URLs, inspects TLS traffic when needed, and includes a built-in web dashboard. Deploy it on any machine — no cloud required.

---

## Highlights

- **YAML Policy Engine** — Block or allow by domain, URL category, path, or full URL pattern
- **2M+ Domain Categories** — Auto-downloads the UT1 Toulouse database on first run
- **Smart TLS Inspection** — Domain-only rules skip MITM entirely; path/URL rules enable selective interception
- **Block Pages** — Users see a clear HTML page explaining why access was denied
- **Built-in Dashboard** — Live sessions, event log, and category chart at `localhost:8765`
- **Access Logging** — JSON-lines to file with configurable filters (`all`, `blocked`, `decisions`)
- **Single Binary** — No external dependencies, no database, no config server

---

## Quick Start

```bash
# Build
go build -o gateweb ./cmd/native

# Run with URL categorization
./gateweb --addr 127.0.0.1:9080 --policy policy.yaml --urldb
```

Create a `policy.yaml`:

```yaml
version: 1
rules:
  - id: block-adult
    name: Block adult content
    priority: 10
    enabled: true
    action: block
    conditions:
      - type: category
        value: adult
    targets:
      - type: all
```

Point your browser proxy to `127.0.0.1:9080` and open `http://localhost:8765` for the dashboard.

### Trust the CA (for HTTPS inspection)

```bash
# macOS
curl -o /tmp/gateweb-ca.pem http://localhost:8765/ca.pem
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/gateweb-ca.pem
```

See [docs/configuration.md](docs/configuration.md) for Windows, Linux, Firefox, Node.js, Python, and Docker instructions.

---

## How It Works

```
Browser ──▶ Gateweb Proxy ──▶ Internet
                │
         ┌──────┴──────┐
         │ Policy Addon│
         │  • Matcher  │  domain / category / path / url
         │  • EventSink│  JSON-lines access log
         │  • BlockPage│  HTML 403 response
         └─────────────┘
```

1. Browser sends `CONNECT` request to establish a tunnel
2. Policy addon evaluates the domain against YAML rules
3. **If domain-only policy**: allowed traffic passes through untouched (no TLS overhead). Blocked domains are selectively intercepted to serve a block page inside the TLS tunnel
4. **If path/URL policy**: traffic is intercepted for full URL visibility
5. Events are emitted to the dashboard and optional file sink

---

## Policy Reference

### Condition Types

| Type | Example | TLS Inspection |
|------|---------|:--------------:|
| `domain` | `*.facebook.com`, `evil.com` | No |
| `category` | `adult`, `gambling`, `malware` | No |
| `path` | `/admin/*`, `/wp-login.php` | Yes |
| `url` | `chatgpt.com/backend-api/*` | Yes |
| `app` | `chatgpt`, `slack` | No |

### Actions

| Action | Description |
|--------|-------------|
| `block` | Returns a 403 block page |
| `allow` | Explicitly allows (overrides later blocks) |

Rules are evaluated by priority (lowest number = highest priority). First match wins.

See [docs/policy.md](docs/policy.md) for the full reference with examples.

---

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `127.0.0.1:8080` | Proxy listen address |
| `--policy` | | Path to `policy.yaml` |
| `--urldb` | `false` | Enable URL categorization |
| `--urldb-path` | `~/.gateweb/categories/urldb.json` | Custom URL database path |
| `--urldb-update` | `false` | Force re-download UT1 |
| `--ca-path` | `~/.gateweb/` | CA certificate storage |
| `--control-port` | `8765` | Dashboard/API port |
| `--event-file` | | JSON-lines access log path |
| `--event-filter` | `all` | `all`, `blocked`, or `decisions` |
| `--quiet` | `false` | Only show warnings and errors |
| `--verbose` | `false` | Debug-level logging |

---

## Dashboard & API

The control server at `localhost:8765` serves a web dashboard and a REST API:

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web dashboard |
| `GET /health` | Health check |
| `POST /shutdown` | Graceful shutdown |
| `GET /ca.pem` | CA certificate (PEM) |
| `GET /api/sessions` | Active proxy sessions |
| `GET /api/events` | Access events (`?filter=blocked&host=...`) |
| `GET /api/events/stats` | Event statistics |
| `GET /api/events/categories` | Category distribution |
| `GET /categories/lookup?domain=X` | Domain category lookup |

See [docs/api.md](docs/api.md) for the full API reference.

---

## Examples

The [`examples/`](examples/) directory has ready-to-use configurations:

| Example | What it does |
|---------|-------------|
| [`basic/`](examples/basic/) | Block specific domains and categories |
| [`categories/`](examples/categories/) | Category-based filtering with custom URL database |
| [`intercept/`](examples/intercept/) | Deep TLS inspection with path/URL rules |
| [`full/`](examples/full/) | Production-like setup with all features |

---

## Project Structure

```
cmd/native/          CLI entry point
addons/              Policy engine, session tracking, event store, block page
providers/local/     YAML policy loader, access log writer
providers/match.go   Domain/path/URL matching logic
urldb/               URL categorization database + UT1 importer
contracts/           Shared types and interfaces
libs/proxy/          HTTP/HTTPS proxy core (CONNECT, MITM, TLS)
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design, request flow, TLS modes |
| [Policy](docs/policy.md) | YAML format, conditions, matching rules |
| [Configuration](docs/configuration.md) | CLI flags, CA trust, proxy setup |
| [API](docs/api.md) | REST API reference |
| [Development](docs/development.md) | Building, testing, extending |

---

## Development

```bash
go build -o gateweb ./cmd/native    # Build
go test -race -cover ./...          # Test
make test                           # Test via CI script
```

Requires **Go 1.24+**.

---

## License

[Apache License 2.0](LICENSE)
