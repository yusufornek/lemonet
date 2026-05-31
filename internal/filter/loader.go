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
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Category rules.Category `json:"category"`
	Count    int            `json:"count"`
	License  string         `json:"license"`
}

var builtinPacks = []struct {
	id, name, file string
	category       rules.Category
}{
	{"ads", "Ads & Trackers", "data/ads.txt", rules.CategoryAds},
	{"social", "Social Media", "data/social.txt", rules.CategorySocial},
}

const builtinLicense = "Built-in (lemonet)"

// DefaultEngine builds a rules engine populated with the small built-in packs and returns
// metadata about each. Larger curated lists are fetched and refreshed separately.
func DefaultEngine() (*rules.Engine, []PackInfo) {
	e := rules.NewEngine()
	var infos []PackInfo
	for _, b := range builtinPacks {
		pack := &rules.ListPack{ID: b.id, Name: b.name, Category: b.category, License: builtinLicense}
		count := 0
		if f, err := packData.Open(b.file); err == nil {
			count = loadDomains(pack.Domains(), f)
			_ = f.Close()
		}
		e.AddPack(pack)
		infos = append(infos, PackInfo{ID: b.id, Name: b.name, Category: b.category, Count: count, License: builtinLicense})
	}
	return e, infos
}

// loadDomains reads a domain list in either plain ("example.com") or hosts ("0.0.0.0 example.com")
// format, ignoring blank and comment lines. It returns the number of domains added.
func loadDomains(set *rules.DomainSet, r io.Reader) int {
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		domain := fields[len(fields)-1]
		set.Add(domain)
		n++
	}
	return n
}
