# Architecture

## Overview

Gateweb is a forward HTTP/HTTPS proxy that inspects traffic, enforces access policies, and categorizes URLs. It runs as a single Go binary with an embedded web dashboard.

```
                          ┌─────────────────────────────────────────┐
                          │              Gateweb Proxy             │
                          │                                         │
  Browser ──HTTP/HTTPS──▶ │  ┌───────────┐    ┌──────────────────┐  │ ──▶ Upstream
                          │  │  Proxy     │───▶│  Policy Addon    │  │     Server
                          │  │  Core      │    │  ┌────────────┐  │  │
                          │  │ (CONNECT,  │    │  │  Matcher    │  │  │
                          │  │  MITM,     │    │  │  (domain,   │  │  │
                          │  │  TLS)      │    │  │   category, │  │  │
                          │  │            │    │  │   path,url) │  │  │
                          │  └───────────┘    │  └────────────┘  │  │
                          │                    │  ┌────────────┐  │  │
                          │                    │  │ Event Sink  │──┼──┼──▶ Log File
                          │                    │  └────────────┘  │  │
                          │                    └──────────────────┘  │
                          │                                         │
                          │  ┌──────────────┐  ┌──────────────────┐  │
                          │  │ Session      │  │ Event Store      │  │
                          │  │ Store        │  │ (in-memory)      │  │
                          │  └──────┬───────┘  └────────┬─────────┘  │
                          │         └──────────┬────────┘            │
                          │                    ▼                     │
                          │  ┌──────────────────────────────────┐    │
                          │  │     Control Server (:8765)       │    │
                          │  │  Dashboard, APIs, CA download    │    │
                          │  └──────────────────────────────────┘    │
                          └─────────────────────────────────────────┘
```

## Request Flow

### 1. HTTP Request (plain text)

```
Browser → Proxy → PolicyAddon.Requestheaders() → Decision → Forward or Block
```

The proxy receives the full HTTP request including URL path. The policy addon evaluates all conditions and either forwards or returns a 403 block page.

### 2. HTTPS Request (CONNECT tunnel)

```
Browser                     Proxy                          Upstream
  │                           │                              │
  │──CONNECT example.com:443─▶│                              │
  │                           │ PolicyAddon (CONNECT)        │
  │                           │   → emit event               │
  │                           │   → do NOT block here        │
  │                           │                              │
  │                           │ ShouldIntercept(host)?       │
  │                           │                              │
  │◀──── 200 OK ─────────────│                              │
  │                           │                              │
  │──TLS handshake───────────▶│                              │
  │                           │                              │
```

At the CONNECT stage, the proxy decides whether to intercept (MITM) or pass through:

**If `ShouldIntercept` returns false** (allowed domain, domain-only policy):
```
  │──TLS data────────────────▶│──────────────────────────────▶│
  │◀─TLS data─────────────────│◀──────────────────────────────│
```
Direct TCP relay. No TLS termination, no overhead.

**If `ShouldIntercept` returns true** (blocked domain, or deep inspection policy):
```
  │──TLS handshake (proxy CA)─▶│                              │
  │                             │──TLS handshake (real cert)──▶│
  │                             │                              │
  │──GET /path ────────────────▶│                              │
  │                             │ PolicyAddon (inner request)  │
  │                             │   → evaluate with full URL   │
  │◀── 403 Block Page ─────────│  (if blocked)                │
  │   or                        │                              │
  │◀── proxied response ───────│◀─────────────────────────────│
```

## TLS Inspection Modes

The proxy automatically selects the inspection mode based on your policy rules:

| Policy conditions | Mode | Behavior |
|-------------------|------|----------|
| Only `domain` + `category` | **Selective** | Only MITM blocked domains (for block page). Allowed traffic passes through untouched. |
| Contains `path`, `url`, `app`, or DLP | **Full** | All HTTPS traffic is MITM'd for complete URL/body visibility. |

This is determined by `PolicyProvider.NeedsInspection()`.

## Package Structure

```
gateweb/
├── cmd/native/          # CLI entry point, dashboard
├── addons/              # Proxy addons (policy, sessions, events, logging)
├── contracts/           # Interfaces and shared types
├── providers/           # Policy evaluation and matching
│   ├── match.go         # Domain, path, URL, category matching
│   └── local/           # YAML policy provider, access log, multi-sink
├── urldb/               # URL categorization database
│   ├── lookup.go        # In-memory categorizer
│   ├── normalize.go     # Domain normalization
│   └── ut1/             # UT1 Toulouse database importer
├── libs/proxy/          # HTTP/HTTPS proxy core (forked go-mitmproxy, MIT)
│   ├── proxy/           # Proxy server, MITM, flows
│   └── cert/            # CA certificate generation
├── examples/            # Example policy configurations
└── docs/                # Documentation
```

## Addon System

The proxy core uses an addon pattern. Each addon implements hooks that are called at different stages of the request lifecycle:

| Hook | When | Used by |
|------|------|---------|
| `Requestheaders` | After request headers are parsed | PolicyAddon, SessionStore |
| `Request` | After full request body is read | LoggerAddon |
| `Response` | After response is received | LoggerAddon |

Addons are registered with `proxy.AddAddon()` and called in registration order.

### PolicyAddon

The main addon. It:
1. Extracts host and path from the request
2. Looks up URL categories from the database
3. Evaluates the request against policy rules
4. Returns a 403 block page if blocked (on inner HTTP requests only)
5. Emits an event to all configured sinks

### SessionStore

Captures completed request/response pairs in a ring buffer for the dashboard API.

### EventStore

Keeps recent policy events in memory for the dashboard's event log and category chart.

## Event Pipeline

```
PolicyAddon
    │
    ▼
MultiSink ──▶ AccessLog (file/stdout, buffered, filtered)
    │
    └────────▶ EventStore (in-memory, ring buffer, dashboard)
```

Events flow through a `MultiSink` that fans out to all registered sinks. Each sink can apply its own filtering (all events, blocked only, decisions only).
