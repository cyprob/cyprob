//go:build ignore

// Command gen_oui regenerates the embedded MAC OUI table from the authoritative
// IEEE registry. The table is generated rather than hand-maintained so vendor
// names are never mistyped.
//
// Usage:
//
//	go run gen_oui.go            # fetch from IEEE and write data/oui.txt.gz
//	go run gen_oui.go -in oui.csv
package main

import (
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const ieeeOUIURL = "https://standards-oui.ieee.org/oui/oui.csv"

// suffixNoise strips legal-entity suffixes that add bytes without adding
// identifying information.
var (
	suffixNoise = regexp.MustCompile(`(?i),?\s*(Inc\.?|Corp\.?|Corporation|Co\.,?\s*Ltd\.?|Ltd\.?|LLC|L\.L\.C\.|GmbH|S\.A\.|S\.A\.S\.|B\.V\.|A/S|Pty|Limited|Company|Co\.)\.?$`)
	whitespace  = regexp.MustCompile(`\s+`)
)

func main() {
	input := flag.String("in", "", "local IEEE oui.csv (default: fetch from IEEE)")
	output := flag.String("out", "data/oui.txt.gz", "output path")
	flag.Parse()

	source, err := openSource(*input)
	if err != nil {
		fatal("open source: %v", err)
	}
	defer source.Close() //nolint:errcheck

	reader := csv.NewReader(source)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		fatal("parse csv: %v", err)
	}

	lines := make([]string, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for i, record := range records {
		if i == 0 || len(record) < 3 {
			continue
		}
		prefix := strings.ToUpper(strings.TrimSpace(record[1]))
		vendor := cleanVendor(record[2])
		if len(prefix) != 6 || vendor == "" {
			continue
		}
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		lines = append(lines, prefix+"\t"+vendor)
	}
	sort.Strings(lines)

	if err := writeGzip(*output, strings.Join(lines, "\n")+"\n"); err != nil {
		fatal("write output: %v", err)
	}
	fmt.Printf("wrote %s (%d OUI prefixes)\n", *output, len(lines))
}

func openSource(path string) (io.ReadCloser, error) {
	if path != "" {
		return os.Open(path) //nolint:gosec // developer-supplied path
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	resp, err := client.Get(ieeeOUIURL) //nolint:noctx // one-shot generator
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close() //nolint:errcheck
		return nil, fmt.Errorf("IEEE returned status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func cleanVendor(raw string) string {
	vendor := whitespace.ReplaceAllString(strings.TrimSpace(raw), " ")
	vendor = strings.Trim(vendor, `"`)
	// Some entries carry two suffixes ("Foo Technologies Co., Ltd.").
	for range 2 {
		vendor = strings.TrimSpace(suffixNoise.ReplaceAllString(vendor, ""))
	}
	return strings.Trim(vendor, " ,.")
}

func writeGzip(path, payload string) error {
	file, err := os.Create(path) //nolint:gosec // developer-supplied path
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck

	writer, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(writer, payload); err != nil {
		return err
	}
	return writer.Close()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen_oui: "+format+"\n", args...)
	os.Exit(1)
}
