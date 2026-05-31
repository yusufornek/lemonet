// Package rules holds lemonet's filtering data model: curated list packs, per-device policy,
// and the matcher that decides whether a domain or flow is blocked.
package rules

import "strings"

// DomainSet matches a domain against a set of suffixes. Adding "example.com" matches
// "example.com" and any subdomain such as "ads.example.com", which is how blocklists are scoped.
type DomainSet struct {
	entries map[string]struct{}
}

func NewDomainSet() *DomainSet {
	return &DomainSet{entries: make(map[string]struct{})}
}

func (s *DomainSet) Add(domain string) {
	d := normalize(domain)
	if d != "" {
		s.entries[d] = struct{}{}
	}
}

func (s *DomainSet) Len() int { return len(s.entries) }

// Match reports whether domain equals or is a subdomain of any entry.
func (s *DomainSet) Match(domain string) bool {
	d := normalize(domain)
	for d != "" {
		if _, ok := s.entries[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}

// normalize lower-cases a domain and strips a trailing dot and leading/trailing whitespace so
// "EXAMPLE.com." and "example.com" compare equal.
func normalize(domain string) string {
	d := strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimSuffix(d, ".")
}

// NormalizeDomain cleans user input ("https://www.YouTube.com/feed") into a bare domain
// ("www.youtube.com") suitable for a rule. It returns "" if the result is not a plausible domain.
func NormalizeDomain(s string) string {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	if i := strings.IndexByte(d, '/'); i >= 0 {
		d = d[:i] // drop any path
	}
	if i := strings.IndexByte(d, ':'); i >= 0 {
		d = d[:i] // drop any port
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" || strings.HasPrefix(d, ".") || strings.ContainsAny(d, " \t@") || !strings.Contains(d, ".") {
		return ""
	}
	return d
}

// matchDomain reports whether pattern (a single suffix) matches domain.
func matchDomain(pattern, domain string) bool {
	p, d := normalize(pattern), normalize(domain)
	return d == p || strings.HasSuffix(d, "."+p)
}
