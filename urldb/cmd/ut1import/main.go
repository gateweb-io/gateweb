// Command ut1import downloads the UT1 URL categorization database and outputs
// a JSON file compatible with the SWG proxy's urldb.CategoriesFile format.
//
// Usage:
//
//	go run ./core/swg/urldb/cmd/ut1import -output categories.json
//	go run ./core/swg/urldb/cmd/ut1import -categories gambling,malware -output categories.json
//	go run ./core/swg/urldb/cmd/ut1import -source blacklists.tar.gz -output categories.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"gateweb/urldb/ut1"
)

func main() {
	output := flag.String("output", "", "output file path (default: stdout)")
	source := flag.String("source", "", "local tar.gz file (skips download)")
	url := flag.String("url", "", "override download URL")
	categories := flag.String("categories", "", "comma-separated category filter")
	flag.Parse()

	opts := ut1.Options{
		SourcePath: *source,
		SourceURL:  *url,
	}

	if *categories != "" {
		for _, c := range strings.Split(*categories, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				opts.Categories = append(opts.Categories, c)
			}
		}
	}

	cf, err := ut1.Import(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "imported %d domains\n", len(cf.Domains))

	data, err := json.Marshal(cf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling JSON: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "written to %s\n", *output)
	} else {
		os.Stdout.Write(data)
	}
}
