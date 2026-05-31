package rules

import "testing"

func TestDomainSetSuffixMatch(t *testing.T) {
	s := NewDomainSet()
	s.Add("example.com")
	cases := map[string]bool{
		"example.com":     true,
		"ads.example.com": true,
		"EXAMPLE.COM.":    true,
		"notexample.com":  false,
		"example.org":     false,
	}
	for domain, want := range cases {
		if got := s.Match(domain); got != want {
			t.Errorf("Match(%q) = %v, want %v", domain, got, want)
		}
	}
}

func TestAllowRuleBeatsPack(t *testing.T) {
	e := NewEngine()
	pack := &ListPack{ID: "games", Category: CategoryGames}
	pack.Domains().Add("game.example")
	e.AddPack(pack)

	pol := DevicePolicy{
		EnabledPacks: []string{"games"},
		CustomRules:  []Rule{{Action: Allow, Domain: "store.game.example"}},
	}
	if !e.DomainBlocked(pol, "play.game.example") {
		t.Error("pack domain should be blocked")
	}
	if e.DomainBlocked(pol, "store.game.example") {
		t.Error("allow rule should override the pack")
	}
}

func TestCustomBlock(t *testing.T) {
	e := NewEngine()
	pol := DevicePolicy{CustomRules: []Rule{{Action: Block, Domain: "tracker.test"}}}
	if !e.DomainBlocked(pol, "a.tracker.test") {
		t.Error("custom block should match subdomain")
	}
	if e.DomainBlocked(pol, "unrelated.test") {
		t.Error("unrelated domain should not be blocked")
	}
}
