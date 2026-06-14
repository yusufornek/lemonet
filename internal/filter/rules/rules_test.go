package rules

import (
	"reflect"
	"sync"
	"testing"
)

// TestListPackDomainsConcurrent guards the lazy-init race that once let a freshly-enabled remote
// pack match an empty set: the relay matcher and the background loader both touch Domains() first.
// Run with -race.
func TestListPackDomainsConcurrent(t *testing.T) {
	p := &ListPack{ID: "x"}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); p.Domains().Set([]string{"bad.test"}) }()
		go func() { defer wg.Done(); _ = p.Domains().Match("a.bad.test") }()
	}
	wg.Wait()
	if !p.Domains().Match("bad.test") {
		t.Error("after concurrent init and set, the pack should contain the domain")
	}
}

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

func TestDomainSetListSortedLimitedCopy(t *testing.T) {
	s := NewDomainSet()
	s.Set([]string{"Beta.test", "alpha.test", "sub.alpha.test", "alpha.test"})

	got := s.List(2)
	want := []string{"alpha.test", "beta.test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List(2) = %v, want %v", got, want)
	}
	got[0] = "changed.test"
	if again := s.List(1); !reflect.DeepEqual(again, []string{"alpha.test"}) {
		t.Fatalf("List result should not alias the set, got %v", again)
	}
	if got := s.List(0); len(got) != 0 {
		t.Fatalf("List(0) = %v, want empty", got)
	}
}

func TestAllowRuleBeatsPack(t *testing.T) {
	e := NewEngine()
	pack := &ListPack{ID: "games", Name: "Games", Category: CategoryGames}
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

	allow := e.Explain(pol, "store.game.example")
	if allow.Blocked || allow.Source != DecisionCustomAllow || allow.MatchedDomain != "store.game.example" {
		t.Fatalf("allow explanation = %+v", allow)
	}
	blocked := e.Explain(pol, "play.game.example")
	if !blocked.Blocked || blocked.Source != DecisionPack || blocked.PackID != "games" || blocked.PackName != "Games" || blocked.MatchedDomain != "game.example" {
		t.Fatalf("pack explanation = %+v", blocked)
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
	blocked := e.Explain(pol, "a.tracker.test")
	if !blocked.Blocked || blocked.Source != DecisionCustomBlock || blocked.MatchedDomain != "tracker.test" {
		t.Fatalf("custom block explanation = %+v", blocked)
	}
	allowed := e.Explain(pol, "unrelated.test")
	if allowed.Blocked || allowed.Source != DecisionNone {
		t.Fatalf("unmatched explanation = %+v", allowed)
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"HTTPS://WWW.YouTube.com/feed": "www.youtube.com",
		"example.com:443":              "example.com",
		" example.com. ":               "example.com",
		"-bad.example":                 "",
		"bad-.example":                 "",
		"bad_label.example":            "",
		"localhost":                    "",
		"192.168.1.1":                  "",
	}
	for in, want := range cases {
		if got := NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
