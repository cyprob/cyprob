//go:build ignore

// Command seed_favicon produces a favicon-corpus entry from a real device.
//
// The corpus is only as good as its provenance, so this tool does the mechanical
// half — fetch the icon, compute the Shodan-convention hash — and then asks for
// the identity rather than guessing it. It also collects whatever the device
// says about itself, so the operator can confirm the identity from the device's
// own statement instead of inference.
//
// Usage:
//
//	go run tools/seed_favicon.go -target http://192.168.1.1
//	go run tools/seed_favicon.go -target https://10.0.0.5:8443 -vendor Fortinet -product FortiGate-100F
//
// Without -vendor/-product it reports the hash and the identity evidence it
// found, so you can verify before committing an entry.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cyprob/cyprob/pkg/modules/scan"
)

// deviceInfoPaths are unauthenticated endpoints that some devices use to state
// their own model. Checked read-only, purely to help the operator confirm what
// the device is.
var deviceInfoPaths = []string{
	"/api/system/deviceinfo",
	"/api/device/information",
	"/description.xml",
	"/DeviceDescription.xml",
}

// identityKeys are field names worth surfacing from a device-info response.
var identityKeys = []string{
	"FriendlyName", "DeviceName", "ModelName", "ProductClass", "Manufacturer",
	"HardwareVersion", "SoftwareVersion", "DeviceIconType", "modelName",
	"friendlyName", "manufacturer",
}

func main() {
	target := flag.String("target", "", "device base URL, e.g. http://192.168.1.1 (required)")
	vendor := flag.String("vendor", "", "verified vendor; omit to only report evidence")
	product := flag.String("product", "", "verified product/model")
	timeout := flag.Duration("timeout", 8*time.Second, "per-request timeout")
	flag.Parse()

	if strings.TrimSpace(*target) == "" {
		fatal("-target is required")
	}
	base := strings.TrimRight(*target, "/")

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // identification, not a trust decision
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	icon, err := fetch(client, base+"/favicon.ico")
	if err != nil {
		fatal("fetch favicon: %v", err)
	}
	if len(icon) == 0 {
		fatal("favicon is empty; nothing to hash")
	}
	hash := scan.FaviconHash(icon)

	fmt.Printf("target : %s\n", base)
	fmt.Printf("favicon: %d bytes\n", len(icon))
	fmt.Printf("hash   : %d\n\n", hash)

	fmt.Println("identity evidence reported by the device itself:")
	if found := collectIdentityEvidence(client, base); len(found) == 0 {
		fmt.Println("  (none found — confirm the model another way before adding an entry)")
	} else {
		for _, line := range found {
			fmt.Printf("  %s\n", line)
		}
	}

	if strings.TrimSpace(*vendor) == "" && strings.TrimSpace(*product) == "" {
		fmt.Println("\nRe-run with -vendor and -product once the identity is confirmed.")
		return
	}

	fmt.Printf("\nCorpus entry for pkg/modules/scan/favicon_corpus.go:\n\n")
	fmt.Printf("\t// Verified %s on a live device.\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Printf("\t%d: {vendor: %q, product: %q},\n", hash, *vendor, *product)
}

func collectIdentityEvidence(client *http.Client, base string) []string {
	var found []string
	for _, path := range deviceInfoPaths {
		body, err := fetch(client, base+path)
		if err != nil || len(body) == 0 {
			continue
		}
		var payload map[string]any
		if json.Unmarshal(body, &payload) == nil {
			for _, key := range identityKeys {
				if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" && value != "-" {
					found = append(found, fmt.Sprintf("%s %s = %q", path, key, value))
				}
			}
			continue
		}
		// Non-JSON (e.g. UPnP XML): surface the raw snippet for the operator.
		if snippet := strings.TrimSpace(string(body)); snippet != "" {
			found = append(found, fmt.Sprintf("%s (non-JSON, first 200 bytes): %.200s", path, snippet))
		}
	}
	return found
}

func fetch(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url) //nolint:noctx // one-shot developer tool
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256*1024))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "seed_favicon: "+format+"\n", args...)
	os.Exit(1)
}
