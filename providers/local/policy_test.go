package local

import (
	"context"
	"gateweb/contracts"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestYAMLPolicyProvider_Evaluate(t *testing.T) {
	policy := `
version: 1
rules:
  - id: block-adult
    name: Block adult content
    priority: 1
    enabled: true
    type: access
    action: block
    conditions:
      - type: category
        value: adult
  - id: block-facebook
    name: Block Facebook
    priority: 2
    enabled: true
    type: access
    action: block
    conditions:
      - type: domain
        value: "*.facebook.com"
  - id: disabled-rule
    name: Disabled rule
    priority: 3
    enabled: false
    type: access
    action: block
    conditions:
      - type: domain
        value: "*.twitter.com"
  - id: allow-all
    name: Allow everything else
    priority: 100
    enabled: true
    type: access
    action: allow
    conditions: []
`
	path := writePolicyFile(t, policy)
	provider, err := NewYAMLPolicyProvider(path)
	require.NoError(t, err)

	tests := []struct {
		name       string
		req        contracts.PolicyRequest
		wantAction contracts.Action
		wantRuleID string
	}{
		{
			"blocks adult category",
			contracts.PolicyRequest{Host: "example.com", Category: "adult"},
			contracts.ActionBlock,
			"block-adult",
		},
		{
			"blocks facebook domain",
			contracts.PolicyRequest{Host: "www.facebook.com"},
			contracts.ActionBlock,
			"block-facebook",
		},
		{
			"blocks facebook bare domain",
			contracts.PolicyRequest{Host: "facebook.com"},
			contracts.ActionBlock,
			"block-facebook",
		},
		{
			"skips disabled rule (twitter allowed)",
			contracts.PolicyRequest{Host: "www.twitter.com"},
			contracts.ActionAllow,
			"allow-all",
		},
		{
			"allows unmatched domains",
			contracts.PolicyRequest{Host: "google.com"},
			contracts.ActionAllow,
			"allow-all",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := provider.Evaluate(context.Background(), tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAction, decision.Action)
			assert.Equal(t, tt.wantRuleID, decision.RuleID)
		})
	}
}

func TestYAMLPolicyProvider_DefaultAllow(t *testing.T) {
	policy := `
version: 1
rules:
  - id: block-malware
    name: Block malware
    priority: 1
    enabled: true
    type: access
    action: block
    conditions:
      - type: category
        value: malware
`
	path := writePolicyFile(t, policy)
	provider, err := NewYAMLPolicyProvider(path)
	require.NoError(t, err)

	decision, err := provider.Evaluate(context.Background(), contracts.PolicyRequest{Host: "safe.com"})
	require.NoError(t, err)
	assert.Equal(t, contracts.ActionAllow, decision.Action)
	assert.Contains(t, decision.Reason, "no rule matched")
}

func TestYAMLPolicyProvider_EmptyPath(t *testing.T) {
	provider, err := NewYAMLPolicyProvider("")
	require.NoError(t, err)

	decision, err := provider.Evaluate(context.Background(), contracts.PolicyRequest{Host: "anything.com"})
	require.NoError(t, err)
	assert.Equal(t, contracts.ActionAllow, decision.Action)
}

func TestYAMLPolicyProvider_NeedsInspection(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   bool
	}{
		{
			"domain only rules - no inspection",
			`
version: 1
rules:
  - id: r1
    name: Block domain
    enabled: true
    type: access
    action: block
    conditions:
      - type: domain
        value: "*.bad.com"
`,
			false,
		},
		{
			"category only rules - no inspection",
			`
version: 1
rules:
  - id: r1
    name: Block category
    enabled: true
    type: access
    action: block
    conditions:
      - type: category
        value: adult
`,
			false,
		},
		{
			"path rule - needs inspection",
			`
version: 1
rules:
  - id: r1
    name: Block path
    enabled: true
    type: access
    action: block
    conditions:
      - type: path
        value: "/admin/*"
`,
			true,
		},
		{
			"url rule - needs inspection",
			`
version: 1
rules:
  - id: r1
    name: Block URL
    enabled: true
    type: access
    action: block
    conditions:
      - type: url
        value: "example.com/secret/*"
`,
			true,
		},
		{
			"app rule - needs inspection",
			`
version: 1
rules:
  - id: r1
    name: Block app
    enabled: true
    type: access
    action: block
    conditions:
      - type: app
        value: chatgpt
`,
			true,
		},
		{
			"DLP rule - needs inspection",
			`
version: 1
rules:
  - id: r1
    name: DLP check
    enabled: true
    type: dlp
    action: block
    dlp:
      patterns:
        - name: SSN
          regex: '\d{3}-\d{2}-\d{4}'
`,
			true,
		},
		{
			"disabled path rule - no inspection",
			`
version: 1
rules:
  - id: r1
    name: Disabled path
    enabled: false
    type: access
    action: block
    conditions:
      - type: path
        value: "/admin/*"
`,
			false,
		},
		{
			"mixed domain and path rules - needs inspection",
			`
version: 1
rules:
  - id: r1
    name: Block domain
    enabled: true
    type: access
    action: block
    conditions:
      - type: domain
        value: "*.bad.com"
  - id: r2
    name: Block path
    enabled: true
    type: access
    action: block
    conditions:
      - type: path
        value: "/secret/*"
`,
			true,
		},
		{
			"empty rules - no inspection",
			`
version: 1
rules: []
`,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writePolicyFile(t, tt.policy)
			provider, err := NewYAMLPolicyProvider(path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, provider.NeedsInspection())
		})
	}
}

func TestYAMLPolicyProvider_Reload(t *testing.T) {
	policy1 := `
version: 1
rules:
  - id: r1
    name: Block domain
    enabled: true
    type: access
    action: block
    conditions:
      - type: domain
        value: "bad.com"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(policy1), 0644))

	provider, err := NewYAMLPolicyProvider(path)
	require.NoError(t, err)

	// Initially blocks bad.com
	d, err := provider.Evaluate(context.Background(), contracts.PolicyRequest{Host: "bad.com"})
	require.NoError(t, err)
	assert.Equal(t, contracts.ActionBlock, d.Action)

	// Update file to allow bad.com
	policy2 := `
version: 2
rules:
  - id: r1
    name: Allow domain
    enabled: true
    type: access
    action: allow
    conditions:
      - type: domain
        value: "bad.com"
`
	require.NoError(t, os.WriteFile(path, []byte(policy2), 0644))
	require.NoError(t, provider.Reload())

	d, err = provider.Evaluate(context.Background(), contracts.PolicyRequest{Host: "bad.com"})
	require.NoError(t, err)
	assert.Equal(t, contracts.ActionAllow, d.Action)

	v, err := provider.Version(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, v)
}

func TestYAMLPolicyProvider_WithTargets(t *testing.T) {
	policy := `
version: 1
rules:
  - id: r1
    name: Block for user1
    enabled: true
    type: access
    action: block
    targets:
      - type: user
        id: user1
    conditions:
      - type: domain
        value: "blocked.com"
`
	path := writePolicyFile(t, policy)
	provider, err := NewYAMLPolicyProvider(path)
	require.NoError(t, err)

	// user1 should be blocked
	d, err := provider.Evaluate(context.Background(), contracts.PolicyRequest{UserID: "user1", Host: "blocked.com"})
	require.NoError(t, err)
	assert.Equal(t, contracts.ActionBlock, d.Action)

	// user2 should be allowed (target doesn't match)
	d, err = provider.Evaluate(context.Background(), contracts.PolicyRequest{UserID: "user2", Host: "blocked.com"})
	require.NoError(t, err)
	assert.Equal(t, contracts.ActionAllow, d.Action)
}

func TestFindPolicyFile(t *testing.T) {
	dir := t.TempDir()

	// No policy file
	assert.Empty(t, FindPolicyFile(dir))

	// Create policy.yaml
	require.NoError(t, os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("version: 1"), 0644))
	assert.Equal(t, filepath.Join(dir, "policy.yaml"), FindPolicyFile(dir))
}
