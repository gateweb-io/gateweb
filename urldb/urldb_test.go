package urldb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"www.Example.COM", "example.com"},
		{"WWW.foo.bar:443", "foo.bar"},
		{"example.com.", "example.com"},
		{"example.com:8080", "example.com"},
		{"www.example.com:443", "example.com"},
		{"EXAMPLE.COM", "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, NormalizeDomain(tt.input))
		})
	}
}

func writeCategoriesFile(t *testing.T, cf *CategoriesFile) string {
	t.Helper()
	data, err := json.Marshal(cf)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "categories.json")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	return path
}

func TestLookup(t *testing.T) {
	path := writeCategoriesFile(t, &CategoriesFile{
		Version: 1,
		Domains: map[string][]string{
			"gambling.com":      {"gambling"},
			"bet365.com":        {"gambling", "betting"},
			"malware.evil.com":  {"malware"},
		},
		PathRules: map[string][]PathRule{
			"youtube.com": {
				{Pattern: "/shorts/*", Categories: []string{"short_video"}},
			},
		},
	})

	cat, err := NewCategorizer(path)
	require.NoError(t, err)
	defer cat.Close()

	t.Run("exact domain match", func(t *testing.T) {
		cats := cat.Lookup("gambling.com", "/")
		assert.Contains(t, cats, "gambling")
	})

	t.Run("multi-category domain", func(t *testing.T) {
		cats := cat.Lookup("bet365.com", "/")
		assert.Contains(t, cats, "gambling")
		assert.Contains(t, cats, "betting")
	})

	t.Run("www prefix stripped", func(t *testing.T) {
		cats := cat.Lookup("www.gambling.com", "/")
		assert.Contains(t, cats, "gambling")
	})

	t.Run("port stripped", func(t *testing.T) {
		cats := cat.Lookup("gambling.com:443", "/")
		assert.Contains(t, cats, "gambling")
	})

	t.Run("not in database", func(t *testing.T) {
		cats := cat.Lookup("httpbin.org", "/get")
		assert.Empty(t, cats)
	})

	t.Run("path rule match", func(t *testing.T) {
		cats := cat.Lookup("youtube.com", "/shorts/abc123")
		assert.Contains(t, cats, "short_video")
	})

	t.Run("path rule no match", func(t *testing.T) {
		cats := cat.Lookup("youtube.com", "/watch?v=abc")
		assert.NotContains(t, cats, "short_video")
	})

	t.Run("case insensitive", func(t *testing.T) {
		cats := cat.Lookup("GAMBLING.COM", "/")
		assert.Contains(t, cats, "gambling")
	})

	t.Run("entries count", func(t *testing.T) {
		assert.Equal(t, 3, cat.Entries())
	})
}

func TestReload(t *testing.T) {
	cf := &CategoriesFile{
		Version: 1,
		Domains: map[string][]string{
			"old.com": {"malware"},
		},
	}
	path := writeCategoriesFile(t, cf)

	cat, err := NewCategorizer(path)
	require.NoError(t, err)

	assert.Contains(t, cat.Lookup("old.com", "/"), "malware")
	assert.Empty(t, cat.Lookup("new.com", "/"))

	// Write updated file and reload.
	cf.Domains = map[string][]string{
		"new.com": {"phishing"},
	}
	data, err := json.Marshal(cf)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o644))

	require.NoError(t, cat.Reload(path))

	assert.Empty(t, cat.Lookup("old.com", "/"))
	assert.Contains(t, cat.Lookup("new.com", "/"), "phishing")
}

func TestParseCategories(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"domains": {
			"example.com": ["ads", "tracking"],
			"WWW.Test.COM": ["test"]
		}
	}`)

	cat, err := ParseCategories(data)
	require.NoError(t, err)

	assert.Equal(t, 2, cat.Entries())
	assert.Contains(t, cat.Lookup("example.com", "/"), "ads")
	assert.Contains(t, cat.Lookup("test.com", "/"), "test") // www. stripped during parse
}

func TestEmptyDatabase(t *testing.T) {
	cat, err := ParseCategories([]byte(`{"version":1,"domains":{}}`))
	require.NoError(t, err)
	assert.Equal(t, 0, cat.Entries())
	assert.Empty(t, cat.Lookup("anything.com", "/"))
}

func TestPathMatching(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		match   bool
	}{
		{"/shorts/*", "/shorts/abc123", true},
		{"/shorts/*", "/shorts/", true},
		{"/shorts/*", "/watch", false},
		{"/api/**", "/api/v1/users", true},
		{"*", "/anything", true},
		{"/exact", "/exact", true},
		{"/exact", "/exact2", false},
		{"*.js", "/bundle.js", true},
		{"*.js", "/bundle.css", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			assert.Equal(t, tt.match, matchPath(tt.pattern, tt.path))
		})
	}
}
