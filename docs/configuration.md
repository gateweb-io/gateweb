# Configuration

## Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `127.0.0.1:8080` | Proxy listen address |
| `--policy` | *(none)* | Path to `policy.yaml` file |
| `--urldb` | `false` | Enable URL categorization (auto-downloads UT1 on first run) |
| `--urldb-path` | `~/.gateweb/categories/urldb.json` | Custom path for URL database |
| `--urldb-update` | `false` | Force re-download the UT1 database |
| `--ca-path` | `~/.gateweb/` | CA certificate storage path |
| `--control-port` | `8765` | Control/dashboard HTTP port |
| `--event-file` | *(none)* | Path for JSON-lines access log |
| `--event-filter` | `all` | Event filter: `all`, `blocked`, `decisions` |
| `--quiet` | `false` | Suppress proxy connection logs (only errors) |
| `--verbose` | `false` | Enable debug-level logging |

## CA Certificate

On first run, the proxy generates a root CA and stores it in `~/.gateweb/` (or the path specified by `--ca-path`).

Files created:
- `gateweb-ca.pem` — CA private key (PEM)
- `gateweb-ca-cert.pem` — CA certificate (PEM)
- `gateweb-ca-cert.cer` — CA certificate (DER)

### Trust the CA

For HTTPS inspection to work, browsers and applications must trust the proxy's CA certificate.

The certificate is at `~/.gateweb/gateweb-ca-cert.pem` (PEM) and `~/.gateweb/gateweb-ca-cert.cer` (DER). You can also download it from the running proxy at `http://localhost:8765/ca.pem`.

#### macOS

```bash
# From the local file
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.gateweb/gateweb-ca-cert.pem

# Or download from the running proxy
curl -o /tmp/gateweb-ca.pem http://localhost:8765/ca.pem
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/gateweb-ca.pem
```

To verify it was added:
```bash
security find-certificate -c "Gateweb" /Library/Keychains/System.keychain
```

To remove later:
```bash
sudo security remove-trusted-cert -d ~/.gateweb/gateweb-ca-cert.pem
```

#### Windows

**Option 1 — GUI:**
1. Double-click `~/.gateweb/gateweb-ca-cert.cer` (or download from `http://localhost:8765/ca.cer`)
2. Click "Install Certificate..."
3. Select "Local Machine" → Next
4. Select "Place all certificates in the following store" → Browse → "Trusted Root Certification Authorities" → OK → Next → Finish

**Option 2 — PowerShell (admin):**
```powershell
Import-Certificate -FilePath "$env:USERPROFILE\.gateweb\gateweb-ca-cert.cer" `
  -CertStoreLocation Cert:\LocalMachine\Root
```

To remove later:
```powershell
Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*Gateweb*"} | Remove-Item
```

#### Linux (Debian/Ubuntu)

```bash
sudo cp ~/.gateweb/gateweb-ca-cert.pem /usr/local/share/ca-certificates/gateweb.crt
sudo update-ca-certificates
```

To remove:
```bash
sudo rm /usr/local/share/ca-certificates/gateweb.crt
sudo update-ca-certificates --fresh
```

#### Linux (RHEL/CentOS/Fedora)

```bash
sudo cp ~/.gateweb/gateweb-ca-cert.pem /etc/pki/ca-trust/source/anchors/gateweb.pem
sudo update-ca-trust
```

To remove:
```bash
sudo rm /etc/pki/ca-trust/source/anchors/gateweb.pem
sudo update-ca-trust
```

#### Firefox

Firefox uses its own certificate store and ignores system certificates.

1. Open Settings → Privacy & Security → Certificates → View Certificates
2. Go to the "Authorities" tab → Import
3. Select `~/.gateweb/gateweb-ca-cert.pem`
4. Check "Trust this CA to identify websites" → OK

#### Node.js / npm

Node.js does not use the system certificate store by default:
```bash
export NODE_EXTRA_CA_CERTS=~/.gateweb/gateweb-ca-cert.pem
```

#### Python (pip/requests)

```bash
export REQUESTS_CA_BUNDLE=~/.gateweb/gateweb-ca-cert.pem
# or for pip
export PIP_CERT=~/.gateweb/gateweb-ca-cert.pem
```

#### Git

```bash
git config --global http.sslCAInfo ~/.gateweb/gateweb-ca-cert.pem
```

#### Docker

Mount the cert into the container and add it to the trust store:
```bash
docker run -v ~/.gateweb/gateweb-ca-cert.pem:/usr/local/share/ca-certificates/gateweb.crt \
  --entrypoint sh your-image -c "update-ca-certificates && your-command"
```

## URL Categorization Database

The URL database maps domains to categories (e.g., `facebook.com → social_networks`). Three ways to use it:

### Auto-download UT1

```bash
go run ./cmd/native --urldb --policy policy.yaml
```

On first run, downloads the UT1 Toulouse blacklist (~2M domains). The database is cached at `~/.gateweb/categories/urldb.json`. Use `--urldb-update` to force a re-download.

### Custom database file

```bash
go run ./cmd/native --urldb-path /path/to/urldb.json --policy policy.yaml
```

### Database JSON format

```json
{
  "version": 1,
  "domains": {
    "pornhub.com": ["adult"],
    "bet365.com": ["gambling"],
    "facebook.com": ["social_networks"]
  },
  "path_rules": {
    "youtube.com": [
      {"pattern": "/shorts/*", "categories": ["short_video"]}
    ]
  }
}
```

### Import from UT1 manually

```bash
go run ./urldb/cmd/ut1import -output urldb.json
```

## Access Logging

Events are written as JSON-lines (one JSON object per line).

### Log to file
```bash
go run ./cmd/native --event-file /var/log/gateweb/events.jsonl --policy policy.yaml
```

### Filter events
```bash
# Only log blocked requests
go run ./cmd/native --event-file events.jsonl --event-filter blocked --policy policy.yaml

# Only log policy decisions (blocked + explicitly allowed)
go run ./cmd/native --event-file events.jsonl --event-filter decisions --policy policy.yaml
```

### Event format

```json
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
```

## Proxy Setup

Gateweb is a standard HTTP/HTTPS forward proxy. Configure your system, browser, or application to route traffic through it.

### macOS

**GUI:** System Settings → Network → Wi-Fi (or your active interface) → Details → Proxies:
- Enable "Web Proxy (HTTP)": Server `127.0.0.1`, Port `8080`
- Enable "Secure Web Proxy (HTTPS)": Server `127.0.0.1`, Port `8080`

**Command line (applies immediately, resets on reboot):**
```bash
# Enable proxy on Wi-Fi
networksetup -setwebproxy Wi-Fi 127.0.0.1 8080
networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8080

# Disable when done
networksetup -setwebproxystate Wi-Fi off
networksetup -setsecurewebproxystate Wi-Fi off
```

**Persistent (survives reboot) — use a PAC file:**
```bash
# Create a PAC file
cat > /tmp/proxy.pac << 'EOF'
function FindProxyForURL(url, host) {
  return "PROXY 127.0.0.1:8080";
}
EOF
```
Then point System Settings → Proxies → Automatic Proxy Configuration to `file:///tmp/proxy.pac`.

### Windows

**GUI:** Settings → Network & Internet → Proxy:
- Enable "Use a proxy server"
- Address: `127.0.0.1`, Port: `8080`

**Command line (PowerShell):**
```powershell
# Enable proxy
netsh winhttp set proxy 127.0.0.1:8080

# Disable
netsh winhttp reset proxy
```

**Registry (system-wide):**
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "127.0.0.1:8080"
```

### Linux

**Environment variables (per-session):**
```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export no_proxy=localhost,127.0.0.1
```

**Persistent (add to `~/.bashrc` or `~/.profile`):**
```bash
echo 'export http_proxy=http://127.0.0.1:8080' >> ~/.bashrc
echo 'export https_proxy=http://127.0.0.1:8080' >> ~/.bashrc
```

**GNOME (Ubuntu):**
```bash
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.http host '127.0.0.1'
gsettings set org.gnome.system.proxy.http port 8080
gsettings set org.gnome.system.proxy.https host '127.0.0.1'
gsettings set org.gnome.system.proxy.https port 8080
```

### Browser-specific

**Firefox:** Settings → General → Network Settings → Manual proxy configuration:
- HTTP Proxy: `127.0.0.1`, Port: `8080`
- Check "Also use this proxy for HTTPS"

**Chrome:** Uses system proxy settings by default. To override:
```bash
# macOS/Linux
google-chrome --proxy-server="http://127.0.0.1:8080"

# Or set per-profile
chromium --proxy-server="http://127.0.0.1:8080"
```

### curl / wget

```bash
curl -x http://127.0.0.1:8080 https://example.com
wget -e http_proxy=http://127.0.0.1:8080 https://example.com
```

### Docker containers

```bash
docker run --network host \
  -e http_proxy=http://127.0.0.1:8080 \
  -e https_proxy=http://127.0.0.1:8080 \
  your-image
```

## File Locations

| Path | Purpose |
|------|---------|
| `~/.gateweb/` | Default CA certificate storage |
| `~/.gateweb/gateweb-ca-cert.pem` | CA certificate (PEM) |
| `~/.gateweb/gateweb-ca.pem` | CA private key |
| `~/.gateweb/categories/urldb.json` | Cached URL database |
