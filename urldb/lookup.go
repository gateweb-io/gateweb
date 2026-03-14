// Package urldb provides domain-to-category lookups for URL categorization.
//
// The server (management plane) aggregates data from any feed (Webroot, UT1,
// threat intelligence, etc.) and produces a single JSON file. The client loads
// this file at startup and uses it for fast in-memory lookups.
//
// JSON format (produced by server, consumed by client):
//
//	{
//	  "version": 1,
//	  "domains": {
//	    "gambling.com": ["gambling"],
//	    "bet365.com": ["gambling", "betting"]
//	  },
//	  "path_rules": {
//	    "youtube.com": [
//	      {"pattern": "/shorts/*", "categories": ["short_video"]}
//	    ]
//	  }
//	}
package urldb

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// CategoriesFile is the JSON format that the server produces.
type CategoriesFile struct {
	Version   int                        `json:"version"`
	Domains   map[string][]string        `json:"domains"`
	PathRules map[string][]PathRule      `json:"path_rules,omitempty"`
}

// PathRule matches a URL path pattern under a specific domain.
type PathRule struct {
	Pattern    string   `json:"pattern"`
	Categories []string `json:"categories"`
}

// Categorizer provides in-memory domain→category lookups.
type Categorizer struct {
	mu        sync.RWMutex
	domains   map[string][]string   // normalized domain → categories
	pathRules map[string][]PathRule // normalized domain → path rules
}

// NewCategorizer loads a categories JSON file and returns a ready-to-use categorizer.
func NewCategorizer(path string) (*Categorizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading categories file: %w", err)
	}
	return ParseCategories(data)
}

// ParseCategories parses categories from JSON bytes.
func ParseCategories(data []byte) (*Categorizer, error) {
	var f CategoriesFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing categories JSON: %w", err)
	}

	// Normalize all domain keys.
	domains := make(map[string][]string, len(f.Domains))
	for domain, cats := range f.Domains {
		domains[NormalizeDomain(domain)] = cats
	}

	pathRules := make(map[string][]PathRule, len(f.PathRules))
	for domain, rules := range f.PathRules {
		pathRules[NormalizeDomain(domain)] = rules
	}

	return &Categorizer{
		domains:   domains,
		pathRules: pathRules,
	}, nil
}

// Lookup returns the categories for a host+path combination.
func (c *Categorizer) Lookup(host, path string) []string {
	norm := NormalizeDomain(host)

	c.mu.RLock()
	defer c.mu.RUnlock()

	base := c.domains[norm]

	// Check path rules for additional categories.
	rules, hasRules := c.pathRules[norm]
	if !hasRules || path == "" {
		return base
	}

	// Copy base slice to avoid mutating the shared map value.
	cats := make([]string, len(base))
	copy(cats, base)
	for _, r := range rules {
		if matchPath(r.Pattern, path) {
			cats = append(cats, r.Categories...)
		}
	}
	return cats
}

// Reload replaces the database from a new file on disk.
func (c *Categorizer) Reload(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading categories file: %w", err)
	}

	fresh, err := ParseCategories(data)
	if err != nil {
		return err
	}

	c.mu.Lock()
	c.domains = fresh.domains
	c.pathRules = fresh.pathRules
	c.mu.Unlock()

	return nil
}

// Close releases resources. Currently a no-op.
func (c *Categorizer) Close() error {
	return nil
}

// Entries returns the number of domain entries in the database.
func (c *Categorizer) Entries() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.domains)
}

// matchPath performs simple glob matching.
func matchPath(pattern, path string) bool {
	if pattern == "*" || pattern == "**" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		return strings.HasPrefix(path, pattern[:len(pattern)-2])
	}
	if strings.HasSuffix(pattern, "/**") {
		return strings.HasPrefix(path, pattern[:len(pattern)-3])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(path, pattern[1:])
	}
	return pattern == path
}
