package addons

import (
	"context"
	"gateweb/contracts"
	"gateweb/libs/proxy/proxy"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPolicyProvider is a simple in-memory policy evaluator for tests.
type mockPolicyProvider struct {
	rules           []contracts.PolicyRule
	needsInspection bool
}

func (m *mockPolicyProvider) Evaluate(_ context.Context, req contracts.PolicyRequest) (*contracts.Decision, error) {
	for _, rule := range m.rules {
		if !rule.Enabled {
			continue
		}
		matched := true
		for _, c := range rule.Conditions {
			switch c.Type {
			case "domain":
				if !domainMatch(c.Value, req.Host) {
					matched = false
				}
			case "category":
				if req.Category != c.Value && !containsStr(req.Categories, c.Value) {
					matched = false
				}
			case "path":
				if req.Path == "" || req.Path != c.Value {
					matched = false
				}
			}
		}
		if matched {
			return &contracts.Decision{
				Action:   rule.Action,
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Reason:   "matched",
			}, nil
		}
	}
	return &contracts.Decision{Action: contracts.ActionAllow, Reason: "default allow"}, nil
}

func (m *mockPolicyProvider) Version(_ context.Context) (int, error)  { return 1, nil }
func (m *mockPolicyProvider) Watch(_ context.Context, _ func()) error { return nil }
func (m *mockPolicyProvider) NeedsInspection() bool                   { return m.needsInspection }

func domainMatch(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if len(pattern) > 2 && pattern[:2] == "*." {
		suffix := pattern[1:]
		if len(host) >= len(suffix) && host[len(host)-len(suffix):] == suffix {
			return true
		}
		if host == pattern[2:] {
			return true
		}
	}
	return false
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// mockEventSink captures emitted events for assertions.
type mockEventSink struct {
	events []*contracts.Event
}

func (m *mockEventSink) Emit(_ context.Context, e *contracts.Event) error {
	m.events = append(m.events, e)
	return nil
}
func (m *mockEventSink) EmitBatch(_ context.Context, events []*contracts.Event) error {
	m.events = append(m.events, events...)
	return nil
}
func (m *mockEventSink) Close() error { return nil }

// newTestFlow creates a Flow suitable for addon testing.
func newTestFlow(method, host, path string) *proxy.Flow {
	u := &url.URL{Host: host, Path: path}
	if method == "CONNECT" {
		u = &url.URL{Host: host}
	}
	return &proxy.Flow{
		Request: &proxy.Request{
			Method: method,
			URL:    u,
		},
	}
}

func TestPolicyAddon_CONNECTDoesNotBlock(t *testing.T) {
	provider := &mockPolicyProvider{
		rules: []contracts.PolicyRule{
			{
				ID:      "block-gambling",
				Name:    "Block gambling",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "domain", Value: "*.gambling.com"},
				},
			},
		},
	}
	sink := &mockEventSink{}
	addon := NewPolicyAddon(provider, sink)

	t.Run("CONNECT to blocked domain does NOT set response (defers to MITM block page)", func(t *testing.T) {
		f := newTestFlow("CONNECT", "www.gambling.com:443", "")
		addon.Requestheaders(f)
		assert.Nil(t, f.Response, "CONNECT should not block; block page served after MITM")
	})

	t.Run("CONNECT to allowed domain does not set response", func(t *testing.T) {
		f := newTestFlow("CONNECT", "google.com:443", "")
		addon.Requestheaders(f)
		assert.Nil(t, f.Response)
	})

	t.Run("events emitted for blocked CONNECT with correct action", func(t *testing.T) {
		sink.events = nil
		f := newTestFlow("CONNECT", "www.gambling.com:443", "")
		addon.Requestheaders(f)
		require.Len(t, sink.events, 1)
		assert.Equal(t, contracts.ActionBlock, sink.events[0].PolicyAction)
		assert.Equal(t, "block-gambling", sink.events[0].PolicyRuleID)
	})

	t.Run("events emitted for allowed CONNECT", func(t *testing.T) {
		sink.events = nil
		f := newTestFlow("CONNECT", "safe.com:443", "")
		addon.Requestheaders(f)
		require.Len(t, sink.events, 1)
		assert.Equal(t, contracts.ActionAllow, sink.events[0].PolicyAction)
	})
}

func TestPolicyAddon_HTTPRequestBlocks(t *testing.T) {
	provider := &mockPolicyProvider{
		rules: []contracts.PolicyRule{
			{
				ID:      "block-gambling",
				Name:    "Block gambling",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "domain", Value: "*.gambling.com"},
				},
			},
			{
				ID:      "block-admin",
				Name:    "Block admin path",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "path", Value: "/admin"},
				},
			},
		},
	}
	sink := &mockEventSink{}
	addon := NewPolicyAddon(provider, sink)

	t.Run("GET to blocked domain returns 403 (inner MITM request)", func(t *testing.T) {
		f := newTestFlow("GET", "www.gambling.com", "/")
		addon.Requestheaders(f)
		require.NotNil(t, f.Response)
		assert.Equal(t, http.StatusForbidden, f.Response.StatusCode)
		assert.NotEmpty(t, f.Response.Body, "should have block page body")
	})

	t.Run("GET to allowed domain does not block", func(t *testing.T) {
		f := newTestFlow("GET", "google.com", "/")
		addon.Requestheaders(f)
		assert.Nil(t, f.Response)
	})

	t.Run("GET with blocked path returns 403", func(t *testing.T) {
		f := newTestFlow("GET", "example.com", "/admin")
		addon.Requestheaders(f)
		require.NotNil(t, f.Response)
		assert.Equal(t, http.StatusForbidden, f.Response.StatusCode)
	})

	t.Run("GET with allowed path does not block", func(t *testing.T) {
		f := newTestFlow("GET", "example.com", "/public")
		addon.Requestheaders(f)
		assert.Nil(t, f.Response)
	})
}

func TestPolicyAddon_ShouldIntercept(t *testing.T) {
	provider := &mockPolicyProvider{
		rules: []contracts.PolicyRule{
			{
				ID:      "block-gambling",
				Name:    "Block gambling",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "domain", Value: "*.gambling.com"},
				},
			},
		},
	}
	addon := NewPolicyAddon(provider, nil)

	t.Run("blocked domain should intercept", func(t *testing.T) {
		assert.True(t, addon.ShouldIntercept("www.gambling.com:443"))
		assert.True(t, addon.ShouldIntercept("gambling.com:443"))
	})

	t.Run("allowed domain should not intercept", func(t *testing.T) {
		assert.False(t, addon.ShouldIntercept("google.com:443"))
		assert.False(t, addon.ShouldIntercept("safe.com:443"))
	})

	t.Run("strips port correctly", func(t *testing.T) {
		assert.True(t, addon.ShouldIntercept("gambling.com:8443"))
		assert.False(t, addon.ShouldIntercept("safe.com:8443"))
	})

	t.Run("nil provider returns false", func(t *testing.T) {
		nilAddon := NewPolicyAddon(nil, nil)
		assert.False(t, nilAddon.ShouldIntercept("anything.com:443"))
	})
}

func TestPolicyAddon_NilProvider(t *testing.T) {
	addon := NewPolicyAddon(nil, nil)
	f := newTestFlow("CONNECT", "anything.com:443", "")
	addon.Requestheaders(f)
	assert.Nil(t, f.Response, "nil provider should not block")
}

func TestPolicyAddon_EventAttribution(t *testing.T) {
	provider := &mockPolicyProvider{
		rules: []contracts.PolicyRule{
			{
				ID:      "block-bad",
				Name:    "Block bad",
				Enabled: true,
				Action:  contracts.ActionBlock,
				Conditions: []contracts.Condition{
					{Type: "domain", Value: "bad.com"},
				},
			},
		},
	}
	sink := &mockEventSink{}
	addon := NewPolicyAddon(provider, sink, WithIdentity("user123", "tenant456"))

	t.Run("CONNECT emits event with identity", func(t *testing.T) {
		sink.events = nil
		f := newTestFlow("CONNECT", "bad.com:443", "")
		addon.Requestheaders(f)

		require.Len(t, sink.events, 1)
		assert.Equal(t, "user123", sink.events[0].UserID)
		assert.Equal(t, "tenant456", sink.events[0].TenantID)
		assert.Equal(t, contracts.ActionBlock, sink.events[0].PolicyAction)
		assert.Equal(t, "block-bad", sink.events[0].PolicyRuleID)
	})

	t.Run("GET block emits event with identity", func(t *testing.T) {
		sink.events = nil
		f := newTestFlow("GET", "bad.com", "/")
		addon.Requestheaders(f)

		require.NotNil(t, f.Response)
		require.Len(t, sink.events, 1)
		assert.Equal(t, "user123", sink.events[0].UserID)
		assert.Equal(t, contracts.ActionBlock, sink.events[0].PolicyAction)
	})
}
