package rules

import "sync"

// Category groups list packs by what they block.
type Category string

const (
	CategoryAds          Category = "ads"
	CategoryGames        Category = "games"
	CategoryStreaming    Category = "streaming"
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

type DecisionSource string

const (
	DecisionNone        DecisionSource = "none"
	DecisionCustomAllow DecisionSource = "custom-allow"
	DecisionCustomBlock DecisionSource = "custom-block"
	DecisionPack        DecisionSource = "pack"
)

type Decision struct {
	Domain        string         `json:"domain"`
	Blocked       bool           `json:"blocked"`
	Source        DecisionSource `json:"source"`
	Action        Action         `json:"action,omitempty"`
	Rule          string         `json:"rule,omitempty"`
	MatchedDomain string         `json:"matchedDomain,omitempty"`
	PackID        string         `json:"packId,omitempty"`
	PackName      string         `json:"packName,omitempty"`
	Category      Category       `json:"category,omitempty"`
	PackLoaded    bool           `json:"packLoaded,omitempty"`
	PackLoading   bool           `json:"packLoading,omitempty"`
	PendingPacks  []string       `json:"pendingPacks,omitempty"`
}

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
	BlockEncryptedDNS bool `json:"blockEncryptedDns"` // common DoT, DoQ, and DNSCrypt ports
	StripECH          bool `json:"stripEch"`          // remove ech= from DNS HTTPS/SVCB answers
	FirefoxCanary     bool `json:"firefoxCanary"`     // NXDOMAIN use-application-dns.net
	BlockVPNPorts     bool `json:"blockVpnPorts"`     // common VPN default ports
}

// ListPack is a curated set of domains for one category. Entries are loaded separately so the
// pack metadata stays small and the data can be refreshed from upstream.
type ListPack struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    Category `json:"category"`
	SourceURL   string   `json:"sourceUrl"`
	License     string   `json:"license"`
	Attribution string   `json:"attribution"`
	once        sync.Once
	domains     *DomainSet `json:"-"`
}

// Domains returns the pack's domain set, creating it exactly once. sync.Once makes the lazy init
// race-free: the relay matcher and a background blocklist loader may both call this for the first
// time concurrently, and both receive the same set (no lost update, no data race).
func (p *ListPack) Domains() *DomainSet {
	p.once.Do(func() {
		if p.domains == nil {
			p.domains = NewDomainSet()
		}
	})
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
	return e.Explain(pol, domain).Blocked
}

func (e *Engine) Explain(pol DevicePolicy, domain string) Decision {
	d := normalize(domain)
	for _, r := range pol.CustomRules {
		if r.Action == Allow && matchDomain(r.Domain, d) {
			return Decision{
				Domain:        d,
				Blocked:       false,
				Source:        DecisionCustomAllow,
				Action:        Allow,
				Rule:          r.Domain,
				MatchedDomain: r.Domain,
			}
		}
	}
	for _, r := range pol.CustomRules {
		if r.Action == Block && matchDomain(r.Domain, d) {
			return Decision{
				Domain:        d,
				Blocked:       true,
				Source:        DecisionCustomBlock,
				Action:        Block,
				Rule:          r.Domain,
				MatchedDomain: r.Domain,
			}
		}
	}
	for _, id := range pol.EnabledPacks {
		if p, ok := e.packs[id]; ok {
			if matched, hit := p.Domains().MatchEntry(d); hit {
				return Decision{
					Domain:        d,
					Blocked:       true,
					Source:        DecisionPack,
					Action:        Block,
					MatchedDomain: matched,
					PackID:        p.ID,
					PackName:      p.Name,
					Category:      p.Category,
				}
			}
		}
	}
	return Decision{Domain: d, Blocked: false, Source: DecisionNone}
}
