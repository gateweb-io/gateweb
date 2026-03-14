# Examples

## basic/ — Domain blocking

Block specific domains by wildcard pattern. No URL database needed.

```bash
go run ./cmd/native \
  --addr 127.0.0.1:9080 \
  --policy examples/basic/policy.yaml
```

Test it:
```bash
# Should be blocked
curl -x http://127.0.0.1:9080 http://www.facebook.com

# Should be allowed
curl -x http://127.0.0.1:9080 http://www.google.com
```

## categories/ — Category-based blocking

Block domains by category using a URL database file.

```bash
go run ./cmd/native \
  --addr 127.0.0.1:9080 \
  --policy examples/categories/policy.yaml \
  --urldb examples/categories/urldb.json
```

Test it:
```bash
# Should be blocked (adult category)
curl -x http://127.0.0.1:9080 http://pornhub.com

# Should be blocked (gambling category)
curl -x http://127.0.0.1:9080 http://bet365.com

# Should be allowed (not in urldb)
curl -x http://127.0.0.1:9080 http://www.google.com
```

### URL database format

```json
{
  "version": 1,
  "domains": {
    "example.com": ["category1", "category2"]
  },
  "path_rules": {
    "youtube.com": [
      {"pattern": "/shorts/*", "categories": ["short_video"]}
    ]
  }
}
```

To import a large URL database from UT1 Toulouse blacklists:
```bash
go run ./urldb/cmd/ut1import -input /path/to/ut1/blacklists -output urldb.json
```

## intercept/ — Deep TLS inspection

Block by URL path and full URL patterns. This enables TLS inspection (MITM) on all HTTPS
traffic so the proxy can see the full URL, not just the domain.

```bash
go run ./cmd/native \
  --addr 127.0.0.1:9080 \
  --policy examples/intercept/policy.yaml \
  --urldb \
  --control-port 8765
```

**Important**: You must trust the proxy's CA certificate for HTTPS inspection to work.
Download it from `http://localhost:8765/ca.pem` and add it to your system/browser trust store.

Test it:
```bash
# Should be blocked (path rule: /admin/*)
curl -x http://127.0.0.1:9080 https://any-site.com/admin/settings

# Should be blocked (URL rule: chatgpt.com/backend-api/*)
curl -x http://127.0.0.1:9080 https://chatgpt.com/backend-api/conversation

# Should be allowed (no matching path/URL rule)
curl -x http://127.0.0.1:9080 https://www.google.com
```

### When is TLS inspection enabled?

The proxy detects whether your policy needs inspection:

- **Domain/category-only rules**: No MITM. Blocked domains are selectively intercepted only to render the block page.
- **Path or URL rules**: Full MITM on all traffic for deep URL visibility.

## full/ — Production-like setup

Combines categories, domain rules, event logging, and all features.

```bash
go run ./cmd/native \
  --addr 127.0.0.1:9080 \
  --policy examples/full/policy.yaml \
  --urldb examples/categories/urldb.json \
  --event-file /tmp/swg-events.jsonl \
  --event-filter all \
  --control-port 8765
```

Then:
- Dashboard: http://localhost:8765
- Download CA cert: http://localhost:8765/ca.pem
- Category lookup: http://localhost:8765/categories/lookup?domain=facebook.com
- Health check: http://localhost:8765/health
- View events: `tail -f /tmp/swg-events.jsonl | jq`

## CA certificate

On first run, the proxy generates a root CA in `~/.gateweb/`. To trust it:

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.gateweb/gateweb-ca-cert.pem

# Or download from the running proxy
curl -o gateweb-ca.pem http://localhost:8765/ca.pem
```

## Policy reference

### Condition types

| Type | Value | Example |
|------|-------|---------|
| `domain` | Wildcard or exact domain | `*.facebook.com`, `evil.com` |
| `category` | URL category name | `adult`, `gambling`, `malware` |
| `path` | URL path pattern (requires TLS inspection) | `/admin/*`, `/wp-login.php` |
| `url` | Full URL pattern (requires TLS inspection) | `chatgpt.com/backend-api/*` |
| `app` | Application name | `chatgpt`, `slack` |

### Actions

| Action | Description |
|--------|-------------|
| `block` | Block the request with a 403 page |
| `allow` | Explicitly allow (overrides later rules) |

### Targets

| Type | Description |
|------|-------------|
| `all` | Applies to all traffic |
| `user` | Applies to a specific user ID |
| `group` | Applies to a specific group ID |
