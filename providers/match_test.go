package providers

import (
	"gateweb/contracts"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{"exact match", "example.com", "example.com", true},
		{"exact no match", "example.com", "other.com", false},
		{"wildcard subdomain", "*.example.com", "sub.example.com", true},
		{"wildcard nested subdomain", "*.example.com", "a.b.example.com", true},
		{"wildcard bare domain", "*.example.com", "example.com", true},
		{"wildcard no match", "*.example.com", "other.com", false},
		{"regex pattern", "^(www\\.)?example\\.com$", "www.example.com", true},
		{"regex pattern bare", "^(www\\.)?example\\.com$", "example.com", true},
		{"regex no match", "^(www\\.)?example\\.com$", "evil.com", false},
		{"empty pattern", "", "example.com", false},
		{"empty host", "example.com", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchDomain(tt.pattern, tt.host))
		})
	}
}

func TestMatchPath(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"exact match", "/api/users", "/api/users", true},
		{"exact no match", "/api/users", "/api/posts", false},
		{"wildcard all star", "*", "/anything", true},
		{"wildcard all double star", "**", "/anything/deep", true},
		{"prefix wildcard", "/api/*", "/api/users", true},
		{"prefix wildcard nested", "/api/*", "/api/users/123", true},
		{"prefix wildcard no match", "/api/*", "/other/path", false},
		{"suffix wildcard", "*.json", "/data/file.json", true},
		{"suffix wildcard no match", "*.json", "/data/file.xml", false},
		{"regex pattern", "^/api/v[0-9]+/", "/api/v2/users", true},
		{"regex no match", "^/api/v[0-9]+/", "/api/latest/users", false},
		{"empty pattern", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchPath(tt.pattern, tt.path))
		})
	}
}

func TestMatchURL(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		path    string
		want    bool
	}{
		{"domain and path", "example.com/api/*", "example.com", "/api/users", true},
		{"domain and path no match path", "example.com/api/*", "example.com", "/other", false},
		{"domain and path no match host", "example.com/api/*", "other.com", "/api/users", false},
		{"domain only (no slash)", "example.com", "example.com", "/anything", true},
		{"wildcard domain with path", "*.example.com/admin/*", "app.example.com", "/admin/settings", true},
		{"exact path", "example.com/login", "example.com", "/login", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchURL(tt.pattern, tt.host, tt.path))
		})
	}
}

func TestMatchCondition(t *testing.T) {
	tests := []struct {
		name string
		cond contracts.Condition
		req  contracts.PolicyRequest
		want bool
	}{
		{
			"domain match",
			contracts.Condition{Type: "domain", Value: "*.facebook.com"},
			contracts.PolicyRequest{Host: "www.facebook.com"},
			true,
		},
		{
			"domain no match",
			contracts.Condition{Type: "domain", Value: "*.facebook.com"},
			contracts.PolicyRequest{Host: "google.com"},
			false,
		},
		{
			"category match primary",
			contracts.Condition{Type: "category", Value: "adult"},
			contracts.PolicyRequest{Category: "adult"},
			true,
		},
		{
			"category match in list",
			contracts.Condition{Type: "category", Value: "gambling"},
			contracts.PolicyRequest{Category: "other", Categories: []string{"news", "gambling"}},
			true,
		},
		{
			"category case insensitive",
			contracts.Condition{Type: "category", Value: "Adult"},
			contracts.PolicyRequest{Category: "adult"},
			true,
		},
		{
			"category no match",
			contracts.Condition{Type: "category", Value: "malware"},
			contracts.PolicyRequest{Category: "news", Categories: []string{"tech"}},
			false,
		},
		{
			"path match",
			contracts.Condition{Type: "path", Value: "/api/*"},
			contracts.PolicyRequest{Path: "/api/data"},
			true,
		},
		{
			"path no match",
			contracts.Condition{Type: "path", Value: "/api/*"},
			contracts.PolicyRequest{Path: "/web/page"},
			false,
		},
		{
			"url match",
			contracts.Condition{Type: "url", Value: "example.com/api/*"},
			contracts.PolicyRequest{Host: "example.com", Path: "/api/users"},
			true,
		},
		{
			"app match",
			contracts.Condition{Type: "app", Value: "slack"},
			contracts.PolicyRequest{AppName: "Slack"},
			true,
		},
		{
			"app no match",
			contracts.Condition{Type: "app", Value: "slack"},
			contracts.PolicyRequest{AppName: "teams"},
			false,
		},
		{
			"unknown type",
			contracts.Condition{Type: "unknown", Value: "x"},
			contracts.PolicyRequest{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchCondition(tt.cond, tt.req))
		})
	}
}

func TestMatchesConditions(t *testing.T) {
	t.Run("empty conditions match everything", func(t *testing.T) {
		assert.True(t, MatchesConditions(nil, contracts.PolicyRequest{}))
	})

	t.Run("all conditions must match", func(t *testing.T) {
		conds := []contracts.Condition{
			{Type: "domain", Value: "example.com"},
			{Type: "path", Value: "/api/*"},
		}
		assert.True(t, MatchesConditions(conds, contracts.PolicyRequest{Host: "example.com", Path: "/api/v1"}))
		assert.False(t, MatchesConditions(conds, contracts.PolicyRequest{Host: "example.com", Path: "/web"}))
		assert.False(t, MatchesConditions(conds, contracts.PolicyRequest{Host: "other.com", Path: "/api/v1"}))
	})
}

func TestMatchesTargets(t *testing.T) {
	tests := []struct {
		name    string
		targets []contracts.Target
		req     contracts.PolicyRequest
		want    bool
	}{
		{"empty targets match all", nil, contracts.PolicyRequest{}, true},
		{"type all", []contracts.Target{{Type: "all"}}, contracts.PolicyRequest{}, true},
		{"user match", []contracts.Target{{Type: "user", ID: "u1"}}, contracts.PolicyRequest{UserID: "u1"}, true},
		{"user no match", []contracts.Target{{Type: "user", ID: "u1"}}, contracts.PolicyRequest{UserID: "u2"}, false},
		{"group match", []contracts.Target{{Type: "group", ID: "g1"}}, contracts.PolicyRequest{GroupIDs: []string{"g1", "g2"}}, true},
		{"group no match", []contracts.Target{{Type: "group", ID: "g3"}}, contracts.PolicyRequest{GroupIDs: []string{"g1", "g2"}}, false},
		{
			"multiple targets any match",
			[]contracts.Target{{Type: "user", ID: "u1"}, {Type: "user", ID: "u2"}},
			contracts.PolicyRequest{UserID: "u2"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MatchesTargets(tt.targets, tt.req))
		})
	}
}
