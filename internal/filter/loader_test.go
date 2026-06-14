package filter

import (
	"sort"
	"testing"
)

func TestManagerRegistersCatalog(t *testing.T) {
	m := NewManager()
	infos := m.Packs()
	if len(infos) != len(packDefs) {
		t.Fatalf("Packs() returned %d packs, want %d", len(infos), len(packDefs))
	}
	for _, info := range infos {
		if _, ok := m.engine.Pack(info.ID); !ok {
			t.Errorf("pack %q not registered in engine", info.ID)
		}
	}
	for _, info := range infos {
		if info.License != "MIT" && info.License != builtinLicense {
			t.Errorf("pack %q has non-permissive license %q", info.ID, info.License)
		}
		if info.Count == 0 || !info.Loaded {
			t.Errorf("pack %q should load an embedded fallback list, got %+v", info.ID, info)
		}
		if len(info.SampleDomains) == 0 {
			t.Errorf("pack %q should expose sample domains, got %+v", info.ID, info)
		}
		if len(info.SampleDomains) > packSampleLimit {
			t.Errorf("pack %q exposes %d sample domains, want at most %d", info.ID, len(info.SampleDomains), packSampleLimit)
		}
		if !sort.StringsAreSorted(info.SampleDomains) {
			t.Errorf("pack %q sample domains are not sorted: %v", info.ID, info.SampleDomains)
		}
		if len(info.SampleDomains) > info.Count {
			t.Errorf("pack %q sample domains exceed count: %+v", info.ID, info)
		}
	}
}

func TestBuiltInPacksIncludeMobileAppDomains(t *testing.T) {
	m := NewManager()
	cases := map[string][]string{
		"ads": {
			"adjust.net",
			"app-measurement.com",
			"appsflyer.com",
			"applovin.com",
			"firebase-settings.crashlytics.com",
			"unityads.unity3d.com",
			"vungle.com",
		},
		"social": {
			"bytefcdn-oversea.com",
			"byteoversea.com",
			"fbcdn.net",
			"cdninstagram.com",
			"discordcdn.com",
			"ig.me",
			"ibytedtos.com",
			"m.me",
			"muscdn.com",
			"telegra.ph",
			"tiktokcdn-us.com",
			"tiktokv.com",
			"twimg.com",
			"sc-cdn.net",
			"redditstatic.com",
			"discordapp.com",
		},
		"streaming": {
			"bamgrid.com",
			"ggpht.com",
			"jtvnw.net",
			"nflximg.net",
			"youtube.com",
			"youtubei.googleapis.com",
			"googlevideo.com",
			"scdn.co",
			"ttvnw.net",
			"withyoutube.com",
			"youtube-ui.l.google.com",
			"youtubeanalytics.com",
			"ytimg.com",
			"ytimg.l.google.com",
			"youtubeembeddedplayer.googleapis.com",
			"youtubekids.com",
			"nflxvideo.net",
			"twitchcdn.net",
		},
		"encrypted-dns": {
			"1dot1dot1dot1.cloudflare-dns.com",
			"dns.controld.com",
			"doh.opendns.com",
			"doh.mullvad.net",
		},
		"vpn": {
			"argotunnel.com",
			"cloudflarewarp.com",
			"mask.icloud.com",
			"mask-h2.icloud.com",
			"cloudflareclient.com",
			"private-relay.apple.com",
			"tailscale.com",
			"warp.dev",
			"zerotier.net",
		},
		"gaming": {
			"ea.com",
			"epicgames.dev",
			"playvalorant.com",
			"rbxcdn.com",
			"riotcdn.net",
			"steam-chat.com",
			"steamcontent.com",
			"xboxservices.com",
			"hoyoverse.com",
		},
		"gambling": {
			"bet365scores.com",
			"draftkingsnetwork.com",
			"fanduel.co.uk",
			"pokerstarscasino.com",
			"sportsbet.io",
		},
	}
	for packID, domains := range cases {
		pack, ok := m.engine.Pack(packID)
		if !ok {
			t.Fatalf("pack %q is not registered", packID)
		}
		for _, domain := range domains {
			if !pack.Domains().Match(domain) {
				t.Errorf("pack %q should match mobile domain %q", packID, domain)
			}
		}
	}
}
