package filter

import (
	"bufio"
	"embed"
	"io"
	"strings"

	"github.com/yusufornek/lemonet/internal/filter/rules"
)

//go:embed data/*.txt
var packData embed.FS

// PackInfo describes an available list pack for the UI.
type PackInfo struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Category    rules.Category `json:"category"`
	Count       int            `json:"count"`
	License     string         `json:"license"`
	Attribution string         `json:"attribution"`
	SourceURL   string         `json:"sourceUrl"`
	Loaded      bool           `json:"loaded"`  // domains are in memory and matching
	Loading     bool           `json:"loading"` // a fetch is in progress
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

// packDefs is the catalog. Remote URLs point at single raw text files in plain or hosts format.
// Licenses: Hagezi = MIT, UT1 (Université Toulouse Capitole) = CC BY-SA (attribution required).
// All remote URLs were verified to return a single plain/hosts-format list of a reasonable size.
const ut1 = "https://raw.githubusercontent.com/olbat/ut1-blacklists/master/blacklists/"

var packDefs = []packDef{
	{id: "ads", name: "Ads & Trackers", category: rules.CategoryAds, license: "MIT", attribution: "HaGeZi", embedFile: "data/ads.txt", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt"},
	{id: "social", name: "Social Media", category: rules.CategorySocial, license: builtinLicense, embedFile: "data/social.txt"},
	{id: "gambling", name: "Gambling", category: rules.CategoryGambling, license: "CC BY-SA", attribution: "Université Toulouse Capitole (UT1)", url: ut1 + "gambling/domains"},
	{id: "vpn", name: "VPN & Proxy", category: rules.CategoryVPN, license: "CC BY-SA", attribution: "Université Toulouse Capitole (UT1)", url: ut1 + "vpn/domains"},
	{id: "gaming", name: "Gaming", category: rules.CategoryGames, license: "CC BY-SA", attribution: "Université Toulouse Capitole (UT1)", url: ut1 + "games/domains"},
	{id: "malware", name: "Malware & Phishing", category: rules.CategoryMalware, license: "CC BY-SA", attribution: "Université Toulouse Capitole (UT1)", url: ut1 + "malware/domains"},
}

// parseList extracts domains from a blocklist in plain ("example.com") or hosts ("0.0.0.0 host")
// format, skipping blank and comment lines. Normalization and de-duplication happen in
// DomainSet.Set. A large buffer tolerates unusually long lines.
func parseList(r io.Reader) []string {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var out []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		fields := strings.Fields(line)
		out = append(out, fields[len(fields)-1])
	}
	return out
}
