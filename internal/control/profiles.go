package control

import "github.com/yusufornek/lemonet/internal/filter/rules"

type PolicyProfile struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	EnabledPacks []string      `json:"enabledPacks"`
	Toggles      rules.Toggles `json:"toggles"`
}

var policyProfiles = []PolicyProfile{
	{
		ID:           "focus",
		Name:         "Focus",
		Description:  "Blocks social, streaming video, gaming, gambling, encrypted DNS, VPN defaults, QUIC, and ECH for distraction control.",
		EnabledPacks: []string{"social", "streaming", "gaming", "gambling", "encrypted-dns", "vpn"},
		Toggles: rules.Toggles{
			BlockQUIC:         true,
			BlockEncryptedDNS: true,
			StripECH:          true,
			FirefoxCanary:     true,
			BlockVPNPorts:     true,
		},
	},
	{
		ID:           "guest",
		Name:         "Guest",
		Description:  "Blocks ads, malware, encrypted DNS, VPN defaults, QUIC, and ECH for untrusted devices.",
		EnabledPacks: []string{"ads", "malware", "encrypted-dns", "vpn"},
		Toggles: rules.Toggles{
			BlockQUIC:         true,
			BlockEncryptedDNS: true,
			StripECH:          true,
			FirefoxCanary:     true,
			BlockVPNPorts:     true,
		},
	},
	{
		ID:           "child",
		Name:         "Child",
		Description:  "Blocks social, streaming video, gaming, gambling, malware, encrypted DNS, VPN defaults, QUIC, and ECH.",
		EnabledPacks: []string{"social", "streaming", "gaming", "gambling", "malware", "encrypted-dns", "vpn"},
		Toggles: rules.Toggles{
			BlockQUIC:         true,
			BlockEncryptedDNS: true,
			StripECH:          true,
			FirefoxCanary:     true,
			BlockVPNPorts:     true,
		},
	},
}

func profileByID(id string) (PolicyProfile, bool) {
	for _, p := range policyProfiles {
		if p.ID == id {
			return cloneProfile(p), true
		}
	}
	return PolicyProfile{}, false
}

func cloneProfile(p PolicyProfile) PolicyProfile {
	p.EnabledPacks = append([]string(nil), p.EnabledPacks...)
	return p
}
