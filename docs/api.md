# Control API

The control server runs on the port specified by `--control-port` (default: 8765) and binds to `127.0.0.1` only.

## Endpoints

### Health & Lifecycle

#### `GET /health`

Returns `ok` with status 200. Use for health checks and readiness probes.

#### `POST /shutdown`

Initiates graceful shutdown of the proxy and control server.

### Dashboard

#### `GET /`

Serves the built-in web dashboard with:
- **Sessions tab:** Real-time view of proxy sessions grouped by domain, with request counts, blocked counts, and per-request details
- **Events tab:** Searchable event log with action badges and category distribution chart
- **Controls:** Refresh, clear, and filter buttons

### Sessions

#### `GET /api/sessions`

Returns all captured proxy sessions (newest last).

```json
[
  {
    "id": "abc-123",
    "timestamp": "2024-03-10T12:00:00Z",
    "method": "GET",
    "host": "example.com",
    "path": "/api/data",
    "proto": "HTTP/1.1",
    "tls": true,
    "request_size": 256,
    "response_status": 200,
    "response_size": 1024,
    "duration_ms": 45,
    "content_type": "application/json"
  }
]
```

Blocked requests include additional fields:
```json
{
  "policy_action": "block",
  "policy_rule": "Block social media"
}
```

#### `GET /api/domains`

Returns sessions grouped by domain with aggregate statistics.

```json
[
  {
    "domain": "example.com",
    "tls": true,
    "request_count": 15,
    "blocked_count": 0,
    "total_bytes": 45000,
    "last_seen": "2024-03-10T12:05:00Z",
    "sessions": [...]
  }
]
```

#### `POST /api/sessions/clear`

Clears all stored sessions. Returns `{"status": "cleared"}`.

### Events

#### `GET /api/events`

Returns policy events. Supports query parameters:

| Parameter | Example | Description |
|-----------|---------|-------------|
| `filter` | `?filter=blocked` | Only return blocked events |
| `host` | `?host=facebook.com` | Only return events for this host |

Both parameters can be combined: `?filter=blocked&host=facebook.com`

```json
[
  {
    "id": "1710000000000-1",
    "timestamp": "2024-03-10T12:00:00Z",
    "request_method": "GET",
    "request_host": "facebook.com",
    "request_path": "/",
    "policy_rule_id": "block-social",
    "policy_action": "block",
    "category": "social_networks",
    "categories": ["social_networks"]
  }
]
```

#### `GET /api/events/stats`

Returns event summary statistics.

```json
{
  "total": 150,
  "blocked": 23,
  "since": "2024-03-10T11:00:00Z"
}
```

#### `GET /api/events/categories`

Returns category distribution sorted by count (descending). Used by the dashboard's pie chart.

```json
[
  {"category": "social_networks", "count": 45},
  {"category": "adult", "count": 12},
  {"category": "uncategorized", "count": 93}
]
```

### Certificates

#### `GET /ca.pem`

Downloads the proxy's root CA certificate in PEM format. Use this to trust the proxy for HTTPS inspection.

#### `GET /ca.cer`

Downloads the proxy's root CA certificate in DER format (for Windows).

### URL Categories

#### `GET /categories/lookup?domain=<domain>`

Looks up the categories for a domain in the URL database.

```json
{
  "domain": "facebook.com",
  "categories": ["social_networks"],
  "entries": 2100000
}
```

If the URL database is not loaded:
```json
{
  "domain": "facebook.com",
  "categories": [],
  "source": "none"
}
```

#### `GET /categories/stats`

Returns URL database statistics.

```json
{
  "loaded": true,
  "entries": 2100000
}
```
