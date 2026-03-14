package ut1

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestArchive creates a gzip-compressed tar archive with the given
// structure. Keys are tar entry paths, values are file contents.
func buildTestArchive(t *testing.T, files map[string]string) *bytes.Reader {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(content)),
			Typeflag: tar.TypeReg,
		}
		require.NoError(t, tw.WriteHeader(hdr))
		_, err := tw.Write([]byte(content))
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	return bytes.NewReader(buf.Bytes())
}

func TestParseArchive(t *testing.T) {
	archive := buildTestArchive(t, map[string]string{
		"blacklists/gambling/domains": "casino.com\nbet365.com\n",
		"blacklists/adult/domains":    "adult-site.com\nbet365.com\n",
	})

	domains, err := ParseArchive(archive, nil)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"gambling"}, domains["casino.com"])
	assert.ElementsMatch(t, []string{"gambling", "adult"}, domains["bet365.com"])
	assert.ElementsMatch(t, []string{"adult"}, domains["adult-site.com"])
}

func TestParseArchive_CategoryFilter(t *testing.T) {
	archive := buildTestArchive(t, map[string]string{
		"blacklists/gambling/domains": "casino.com\n",
		"blacklists/adult/domains":    "adult-site.com\n",
		"blacklists/malware/domains":  "evil.com\n",
	})

	filter := map[string]bool{"gambling": true}
	domains, err := ParseArchive(archive, filter)
	require.NoError(t, err)

	assert.Equal(t, []string{"gambling"}, domains["casino.com"])
	assert.Empty(t, domains["adult-site.com"])
	assert.Empty(t, domains["evil.com"])
	assert.Len(t, domains, 1)
}

func TestParseArchive_SkipsURLFiles(t *testing.T) {
	archive := buildTestArchive(t, map[string]string{
		"blacklists/gambling/domains": "casino.com\n",
		"blacklists/gambling/urls":    "http://casino.com/slots\n",
	})

	domains, err := ParseArchive(archive, nil)
	require.NoError(t, err)

	assert.Equal(t, []string{"gambling"}, domains["casino.com"])
	// The URL entry should not appear as a domain.
	assert.Empty(t, domains["http://casino.com/slots"])
	assert.Len(t, domains, 1)
}

func TestParseArchive_NormalizeDomains(t *testing.T) {
	archive := buildTestArchive(t, map[string]string{
		"blacklists/adult/domains": "WWW.Example.COM\nSIMPLE.org\n",
	})

	domains, err := ParseArchive(archive, nil)
	require.NoError(t, err)

	// www. stripped, lowercased
	assert.Equal(t, []string{"adult"}, domains["example.com"])
	assert.Equal(t, []string{"adult"}, domains["simple.org"])
	assert.Empty(t, domains["WWW.Example.COM"])
}

func TestParseArchive_EmptyAndCommentLines(t *testing.T) {
	archive := buildTestArchive(t, map[string]string{
		"blacklists/malware/domains": "# This is a comment\n\nevil.com\n  \n# Another comment\nbad.org\n",
	})

	domains, err := ParseArchive(archive, nil)
	require.NoError(t, err)

	assert.Equal(t, []string{"malware"}, domains["evil.com"])
	assert.Equal(t, []string{"malware"}, domains["bad.org"])
	assert.Len(t, domains, 2)
}
