package filter

import (
	"bufio"
	"embed"
	"fmt"
	"io"
	"strings"

	"github.com/yusufornek/lemonet/internal/filter/rules"
)

//go:embed data/*.txt
var packData embed.FS

// PackInfo describes an available list pack for the UI.
type PackInfo struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Category      rules.Category `json:"category"`
	Count         int            `json:"count"`
	SampleDomains []string       `json:"sampleDomains,omitempty"`
	License       string         `json:"license"`
	Attribution   string         `json:"attribution"`
	SourceURL     string         `json:"sourceUrl"`
	Loaded        bool           `json:"loaded"`  // domains are in memory and matching
	Loading       bool           `json:"loading"` // a fetch is in progress
}

const builtinLicense = "Built-in (lemonet)"

// packDef declares an available pack. A def may carry an embedded list (offline, loaded at start)
// and/or a remote URL (downloaded on demand when the user enables it). When both are set, the
// embedded list is the offline fallback and the remote list supersedes it once fetched.
type packDef struct {
	id, name    string
	category    rules.Category
	license     string
	attribution string
	embedFile   string // path within data/, "" if none
	url         string // remote list URL, "" if built-in only
}

var packDefs = []packDef{
	{id: "ads", name: "Ads & Trackers", category: rules.CategoryAds, license: "MIT", attribution: "HaGeZi", embedFile: "data/ads.txt", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"},
	{id: "social", name: "Social Media", category: rules.CategorySocial, license: builtinLicense, embedFile: "data/social.txt"},
	{id: "streaming", name: "Streaming Video", category: rules.CategoryStreaming, license: builtinLicense, embedFile: "data/streaming.txt"},
	{id: "encrypted-dns", name: "Encrypted DNS", category: rules.CategoryEncryptedDNS, license: builtinLicense, embedFile: "data/encrypted_dns.txt"},
	{id: "vpn", name: "VPN & Proxy", category: rules.CategoryVPN, license: builtinLicense, embedFile: "data/vpn.txt"},
	{id: "gaming", name: "Gaming", category: rules.CategoryGames, license: builtinLicense, embedFile: "data/gaming.txt"},
	{id: "gambling", name: "Gambling", category: rules.CategoryGambling, license: builtinLicense, embedFile: "data/gambling.txt"},
	{id: "malware", name: "Malware & Phishing", category: rules.CategoryMalware, license: builtinLicense, embedFile: "data/malware.txt"},
}

// parseList extracts domains from a blocklist in plain ("example.com") or hosts ("0.0.0.0 host")
// format, skipping blank and comment lines. Normalization and de-duplication happen in
// DomainSet.Set. A large buffer tolerates unusually long lines.
func parseList(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		if cut := strings.IndexByte(line, '#'); cut >= 0 {
			line = strings.TrimSpace(line[:cut])
			if line == "" {
				continue
			}
		}
		fields := strings.Fields(line)
		out = append(out, fields[len(fields)-1])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("filter: parse list: %w", err)
	}
	return out, nil
}
