package rules

// Category groups list packs by what they block.
type Category string

const (
	CategoryAds          Category = "ads"
	CategoryGames        Category = "games"
	CategoryVPN          Category = "vpn"
	CategorySocial       Category = "social"
	CategoryAdult        Category = "adult"
	CategoryGambling     Category = "gambling"
	CategoryMalware      Category = "malware"
	CategoryEncryptedDNS Category = "encrypted-dns"
	CategoryCustom       Category = "custom"
)

// Action is how a custom rule resolves a match.
type Action string

const (
	Block Action = "block"
	Allow Action = "allow"
)

// Rule is a single user-defined domain rule. Allow rules take precedence over block rules and
// over list packs, so a user can punch a hole in a category they otherwise block.
type Rule struct {
	Action Action `json:"action"`
	Domain string `json:"domain"`
}

// Toggles are the per-device layer-3/4 controls that complement domain blocking. They address
// the channels that defeat naive DNS filtering.
type Toggles struct {
	BlockQUIC         bool `json:"blockQuic"`         // UDP/443, forcing TCP fallback where SNI is readable
	BlockEncryptedDNS bool `json:"blockEncryptedDns"` // TCP/UDP 853
	StripECH          bool `json:"stripEch"`          // remove ech= from DNS HTTPS/SVCB answers
	FirefoxCanary     bool `json:"firefoxCanary"`     // NXDOMAIN use-application-dns.net
	BlockVPNPorts     bool `json:"blockVpnPorts"`     // common VPN default ports
}

// ListPack is a curated set of domains for one category. Entries are loaded separately so the
// pack metadata stays small and the data can be refreshed from upstream.
type ListPack struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Category    Category   `json:"category"`
	SourceURL   string     `json:"sourceUrl"`
	License     string     `json:"license"`
	Attribution string     `json:"attribution"`
	domains     *DomainSet `json:"-"`
}

func (p *ListPack) Domains() *DomainSet {
	if p.domains == nil {
		p.domains = NewDomainSet()
	}
	return p.domains
}

// DevicePolicy is the filtering configuration for one device, identified by MAC.
type DevicePolicy struct {
	MAC          string   `json:"mac"`
	EnabledPacks []string `json:"enabledPacks"`
	CustomRules  []Rule   `json:"customRules"`
	Toggles      Toggles  `json:"toggles"`
}

// Engine evaluates policy against domains. It holds the loaded list packs shared across devices.
type Engine struct {
	packs map[string]*ListPack
}

func NewEngine() *Engine {
	return &Engine{packs: make(map[string]*ListPack)}
}

func (e *Engine) AddPack(p *ListPack) { e.packs[p.ID] = p }

func (e *Engine) Pack(id string) (*ListPack, bool) {
	p, ok := e.packs[id]
	return p, ok
}

// DomainBlocked decides a domain for a device. Order: allow rules win, then block rules, then
// any enabled list pack. A domain with no match is allowed.
func (e *Engine) DomainBlocked(pol DevicePolicy, domain string) bool {
	for _, r := range pol.CustomRules {
		if r.Action == Allow && matchDomain(r.Domain, domain) {
			return false
		}
	}
	for _, r := range pol.CustomRules {
		if r.Action == Block && matchDomain(r.Domain, domain) {
			return true
		}
	}
	for _, id := range pol.EnabledPacks {
		if p, ok := e.packs[id]; ok && p.Domains().Match(domain) {
			return true
		}
	}
	return false
}
