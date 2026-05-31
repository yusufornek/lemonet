// Package l4 decides transport-layer policy: the per-device toggles that close the channels
// which bypass domain filtering, such as QUIC, encrypted DNS, and common VPN ports.
package l4

import "github.com/yusufornek/lemonet/internal/filter/rules"

type Proto int

const (
	TCP Proto = iota
	UDP
)

// Flow is the minimal transport view of a packet needed for a policy decision.
type Flow struct {
	Proto   Proto
	DstPort uint16
}

const (
	portHTTPS       = 443 // QUIC/HTTP3 runs here over UDP
	portEncryptedDS = 853 // DoT and DoQ
)

// vpnDefaultPorts are the well-known default ports for common VPN protocols. Ports are
// configurable, so this catches default setups only; obfuscated tunnels over 443 are not here.
var vpnDefaultPorts = map[uint16]struct{}{
	1194:  {}, // OpenVPN
	500:   {}, // IKE
	4500:  {}, // IPsec NAT traversal
	51820: {}, // WireGuard
}

// Blocked reports whether the toggles drop this flow.
func Blocked(t rules.Toggles, f Flow) bool {
	if t.BlockQUIC && f.Proto == UDP && f.DstPort == portHTTPS {
		return true
	}
	if t.BlockEncryptedDNS && f.DstPort == portEncryptedDS {
		return true
	}
	if t.BlockVPNPorts {
		if _, ok := vpnDefaultPorts[f.DstPort]; ok {
			return true
		}
	}
	return false
}
