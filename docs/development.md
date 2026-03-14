# Development

## Prerequisites

- Go 1.24+

## Build

```bash
# Build the binary
go build -o gateweb ./cmd/native

# Build all packages (check for compilation errors)
go build ./...
```

## Test

```bash
# Run all tests with race detection
make test

# Or directly
go test -race -cover ./...

# Run tests for a specific package
go test -v ./addons/...
go test -v ./providers/...
go test -v ./urldb/...

# Run a single test
go test -v -run TestPolicyAddon_ShouldIntercept ./addons/...
```

## Project Structure

```
cmd/native/          Entry point and embedded dashboard
addons/              Proxy addons (policy enforcement, sessions, events)
contracts/           Shared interfaces and types
providers/           Policy evaluation logic
  match.go           Condition matching (domain, path, url, category)
  local/             YAML file provider, access log, multi-sink
urldb/               URL categorization
  lookup.go          In-memory categorizer
  ut1/               UT1 Toulouse database importer
libs/proxy/          HTTP/HTTPS proxy core (MIT licensed, forked from go-mitmproxy)
examples/            Example policy configurations
docs/                Documentation
```

## Key Interfaces

### `contracts.PolicyProvider`

Implement this to add a new policy source (e.g., database-backed, remote API).

```go
type PolicyProvider interface {
    Evaluate(ctx context.Context, req PolicyRequest) (*Decision, error)
    Version(ctx context.Context) (int, error)
    Watch(ctx context.Context, callback func()) error
    NeedsInspection() bool
}
```

### `contracts.EventSink`

Implement this to add a new event destination (e.g., Kafka, webhook).

```go
type EventSink interface {
    Emit(ctx context.Context, event *Event) error
    EmitBatch(ctx context.Context, events []*Event) error
    Close() error
}
```

### `addons.CategorySource`

Implement this for dynamic URL category sources (e.g., remote database that polls for updates).

```go
type CategorySource interface {
    Categorizer() *urldb.Categorizer
}
```

## Adding a New Condition Type

1. Add the type string to `contracts.Condition` documentation in `contracts/types.go`
2. Add a case to `providers.MatchCondition()` in `providers/match.go`
3. Update `NeedsInspection()` in `providers/local/policy.go` if the new type requires TLS inspection
4. Add tests in `providers/match_test.go`
5. Document the new type in `docs/policy.md`

## Adding a New Addon

1. Create a new file in `addons/`
2. Embed `proxy.BaseAddon` for default no-op implementations
3. Override the hooks you need (`Requestheaders`, `Request`, `Response`)
4. Register with `proxy.AddAddon()` in `cmd/native/main.go`

```go
type MyAddon struct {
    proxy.BaseAddon
}

func (a *MyAddon) Requestheaders(f *proxy.Flow) {
    // inspect f.Request
}
```

## Testing Conventions

- Table-driven tests with `t.Run()` subtests
- `testify/assert` for assertions, `testify/require` for setup failures
- Integration tests use real proxy instances with TLS backends
- Race detector enabled by default (`-race` flag)

## Dependencies

| Library | Purpose | License |
|---------|---------|---------|
| [go-mitmproxy](https://github.com/lqqyt2423/go-mitmproxy) | HTTP/HTTPS proxy core | MIT |
| [logrus](https://github.com/sirupsen/logrus) | Structured logging (proxy lib) | MIT |
| [yaml.v3](https://gopkg.in/yaml.v3) | Policy YAML parsing | Apache 2.0 |
| [testify](https://github.com/stretchr/testify) | Test assertions | MIT |
