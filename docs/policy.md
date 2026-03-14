# Policy Reference

## Policy File Format

Policies are YAML files with a versioned list of rules. Rules are evaluated top-to-bottom by priority (lowest number = highest priority). First matching rule wins.

```yaml
version: 1
rules:
  - id: block-adult          # unique identifier
    name: Block adult content # human-readable name
    priority: 1               # lower = higher priority
    enabled: true             # can be disabled without removing
    type: access              # rule type
    action: block             # what to do when matched
    conditions:               # all must match (AND logic)
      - type: category
        value: adult
    targets:                  # who this applies to (optional)
      - type: all
```

If no rule matches a request, the default action is **allow**.

## Condition Types

### `domain` — Match by hostname

Matches the request's target hostname. Case-insensitive.

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `facebook.com` | `facebook.com` | `www.facebook.com` |
| `*.facebook.com` | `www.facebook.com`, `m.facebook.com`, `facebook.com` | `notfacebook.com` |

**TLS inspection required:** No. Domain is visible from the CONNECT request and SNI.

### `category` — Match by URL category

Matches against categories from the URL categorization database. Case-insensitive.

```yaml
conditions:
  - type: category
    value: adult
```

Common categories (from UT1 database): `adult`, `gambling`, `malware`, `phishing`, `social_networks`, `games`, `shopping`, `news`, `finance`, `education`.

The full category list depends on your URL database. Use the `/categories/lookup?domain=example.com` API to check what categories a domain belongs to.

**TLS inspection required:** No. Category is resolved from the domain name.

### `path` — Match by URL path

Matches the request URL path. Requires TLS inspection since the path is only visible after decrypting the traffic.

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `/admin/*` | `/admin/users`, `/admin/settings` | `/about`, `/administrator` |
| `*.php` | `/wp-login.php`, `/config.php` | `/wp-login.html` |
| `/wp-login.php` | `/wp-login.php` (exact) | `/wp-login.php?foo=1` |

Supports:
- **Exact match:** `/specific/path`
- **Prefix match:** `/prefix/*`
- **Suffix match:** `*.extension`
- **Regex:** Patterns containing `^$+()[]{}|` are treated as regular expressions

**TLS inspection required:** Yes. Enables full MITM on all traffic.

### `url` — Match by full URL (domain + path)

Combines domain and path matching in a single condition. Format: `domain/path`.

```yaml
conditions:
  - type: url
    value: "chatgpt.com/backend-api/*"
```

The domain part supports wildcards (`*.google.com/upload/*`). The path part supports prefix, suffix, and regex matching.

**TLS inspection required:** Yes.

### `app` — Match by application name

Matches against a detected application name. Case-insensitive.

```yaml
conditions:
  - type: app
    value: chatgpt
```

**TLS inspection required:** No (resolved from domain mapping).

## Actions

| Action | Behavior |
|--------|----------|
| `block` | Returns a 403 page with an HTML block page showing the rule name and reason |
| `allow` | Explicitly allows the request (useful to override later block rules) |

## Targets

Targets control who a rule applies to. If no targets are specified, the rule applies to all traffic.

```yaml
targets:
  - type: all                # applies to everyone
  - type: user
    id: "user-123"           # specific user
  - type: group
    id: "engineering"        # specific group
```

| Type | Description |
|------|-------------|
| `all` | Matches all requests |
| `user` | Matches requests from a specific user ID |
| `group` | Matches requests from users in a specific group |

## Rule Evaluation Order

1. Rules are checked in order of `priority` (lowest number first)
2. For each rule: all `conditions` must match (AND logic)
3. For each rule: at least one `target` must match (OR logic), or no targets = matches all
4. First matching rule determines the action
5. If no rule matches → **allow**

## TLS Inspection Detection

The proxy automatically determines the inspection mode:

- **If all conditions are `domain` or `category`:** Selective mode. Only blocked domains are intercepted to render the block page. Allowed traffic flows through without TLS overhead.
- **If any condition is `path`, `url`, `app`, or DLP is configured:** Full inspection mode. All HTTPS traffic is intercepted for complete URL visibility.

You don't need to configure this manually — it is derived from your policy rules.

## Examples

### Block social media

```yaml
version: 1
rules:
  - id: block-social
    name: Block social media
    priority: 10
    enabled: true
    type: access
    action: block
    conditions:
      - type: category
        value: social_networks
```

### Block file uploads to specific services

```yaml
version: 1
rules:
  - id: block-gdrive-upload
    name: Block Google Drive uploads
    priority: 10
    enabled: true
    type: access
    action: block
    conditions:
      - type: url
        value: "*.google.com/upload/*"
```

### Allow specific domain, block the rest of a category

```yaml
version: 1
rules:
  - id: allow-wikipedia
    name: Allow Wikipedia
    priority: 1
    enabled: true
    type: access
    action: allow
    conditions:
      - type: domain
        value: "*.wikipedia.org"

  - id: block-all-social
    name: Block social media
    priority: 10
    enabled: true
    type: access
    action: block
    conditions:
      - type: category
        value: social_networks
```

### Block admin panels across all sites

```yaml
version: 1
rules:
  - id: block-admin
    name: Block admin panels
    priority: 5
    enabled: true
    type: access
    action: block
    conditions:
      - type: path
        value: "/admin/*"
```
