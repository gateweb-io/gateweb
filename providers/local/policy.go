package local

import (
	"context"
	"gateweb/contracts"
	"gateweb/providers"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// policyFile is the YAML structure for a local policy file.
type policyFile struct {
	Version int                    `yaml:"version"`
	Rules   []contracts.PolicyRule `yaml:"rules"`
}

// YAMLPolicyProvider evaluates requests against rules loaded from a YAML file.
type YAMLPolicyProvider struct {
	mu      sync.RWMutex
	rules   []contracts.PolicyRule
	version int
	path    string
}

// NewYAMLPolicyProvider loads policy rules from a YAML file.
// If path is empty, it returns a provider that allows everything.
func NewYAMLPolicyProvider(path string) (*YAMLPolicyProvider, error) {
	p := &YAMLPolicyProvider{path: path}
	if path == "" {
		return p, nil
	}

	if err := p.load(); err != nil {
		return nil, fmt.Errorf("loading policy %s: %w", path, err)
	}
	return p, nil
}

func (p *YAMLPolicyProvider) load() error {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	var pf policyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return fmt.Errorf("parsing policy YAML: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = pf.Rules
	p.version = pf.Version
	return nil
}

// Evaluate checks the request against rules top-to-bottom; first match wins.
// If no rule matches, the default decision is allow.
func (p *YAMLPolicyProvider) Evaluate(_ context.Context, req contracts.PolicyRequest) (*contracts.Decision, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, rule := range p.rules {
		if !rule.Enabled {
			continue
		}
		if providers.MatchesTargets(rule.Targets, req) && providers.MatchesConditions(rule.Conditions, req) {
			return &contracts.Decision{
				Action:   rule.Action,
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Reason:   fmt.Sprintf("matched rule %q", rule.Name),
			}, nil
		}
	}

	// Default: allow
	return &contracts.Decision{
		Action: contracts.ActionAllow,
		Reason: "no rule matched, default allow",
	}, nil
}

func (p *YAMLPolicyProvider) Version(_ context.Context) (int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version, nil
}

// Watch is a placeholder for file-watching support.
// Callers can use Reload() to explicitly re-read the policy file.
func (p *YAMLPolicyProvider) Watch(ctx context.Context, callback func()) error {
	if p.path == "" {
		return nil
	}
	// Placeholder: in production, use fsnotify here.
	// For now, callers can call Reload() explicitly.
	return nil
}

// Reload re-reads the policy file from disk.
func (p *YAMLPolicyProvider) Reload() error {
	if p.path == "" {
		return nil
	}
	return p.load()
}

// NeedsInspection returns true if any rule requires TLS inspection.
// Domain and category rules can be enforced at the CONNECT level without MITM.
// Path, app, DLP, and other conditions require decrypted traffic.
func (p *YAMLPolicyProvider) NeedsInspection() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, rule := range p.rules {
		if !rule.Enabled {
			continue
		}
		if rule.DLP != nil && len(rule.DLP.Patterns) > 0 {
			return true
		}
		for _, c := range rule.Conditions {
			switch c.Type {
			case "domain", "category":
				// These work without inspection
			default:
				// path, app, time_range, etc. need inspection
				return true
			}
		}
	}
	return false
}

// FindPolicyFile looks for policy.yaml in common locations.
func FindPolicyFile(configDir string) string {
	candidates := []string{
		filepath.Join(configDir, "policy.yaml"),
		filepath.Join(configDir, "policy.yml"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
