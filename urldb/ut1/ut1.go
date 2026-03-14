// Package ut1 downloads and parses the UT1 open-source URL categorization
// database (https://dsi.ut-capitole.fr/blacklists/) into a format compatible
// with the urldb.CategoriesFile JSON structure.
package ut1

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"gateweb/urldb"
)

const DefaultURL = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"

// Options configures how Import fetches and filters the UT1 data.
type Options struct {
	// SourceURL overrides the default download URL.
	SourceURL string
	// SourcePath loads from a local tar.gz file instead of downloading.
	SourcePath string
	// Categories filters to only these categories. Nil or empty means all.
	Categories []string
}

// Import downloads (or opens) the UT1 archive and returns a CategoriesFile.
func Import(opts Options) (*urldb.CategoriesFile, error) {
	var r io.ReadCloser

	if opts.SourcePath != "" {
		f, err := os.Open(opts.SourcePath)
		if err != nil {
			return nil, fmt.Errorf("opening source file: %w", err)
		}
		r = f
	} else {
		url := opts.SourceURL
		if url == "" {
			url = DefaultURL
		}
		client := &http.Client{Timeout: 5 * time.Minute}
		resp, err := client.Get(url)
		if err != nil {
			return nil, fmt.Errorf("downloading UT1 archive: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("downloading UT1 archive: HTTP %d", resp.StatusCode)
		}
		r = resp.Body
	}
	defer r.Close()

	var filter map[string]bool
	if len(opts.Categories) > 0 {
		filter = make(map[string]bool, len(opts.Categories))
		for _, c := range opts.Categories {
			filter[c] = true
		}
	}

	domains, err := ParseArchive(r, filter)
	if err != nil {
		return nil, err
	}

	return &urldb.CategoriesFile{
		Version: 1,
		Domains: domains,
	}, nil
}

// ParseArchive reads a gzip-compressed tar archive in UT1 format and extracts
// domain-to-category mappings. The archive contains entries like:
//
//	blacklists/<category>/domains
//	blacklists/<category>/urls
//
// Only "domains" files are processed; "urls" files are skipped.
// If categoryFilter is non-nil, only categories present in the map are included.
func ParseArchive(r io.Reader, categoryFilter map[string]bool) (map[string][]string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("opening gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	domains := make(map[string][]string)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entry: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// Match pattern: <anything>/<category>/domains
		base := path.Base(hdr.Name)
		if base != "domains" {
			continue
		}

		dir := path.Dir(hdr.Name)
		category := path.Base(dir)
		if category == "" || category == "." {
			continue
		}

		if categoryFilter != nil && !categoryFilter[category] {
			continue
		}

		scanner := bufio.NewScanner(tr)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			domain := urldb.NormalizeDomain(line)
			if domain == "" {
				continue
			}

			// Deduplicate categories for this domain.
			existing := domains[domain]
			found := false
			for _, c := range existing {
				if c == category {
					found = true
					break
				}
			}
			if !found {
				domains[domain] = append(existing, category)
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("scanning domains for category %s: %w", category, err)
		}
	}

	return domains, nil
}
