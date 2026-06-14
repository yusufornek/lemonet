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
	portDoQAlt      = 784
	portEncryptedDS = 853
	portDNSCrypt    = 5353
	portDNSCryptAlt = 5443
	portDoQAlt2     = 8853
)

var quicPorts = map[uint16]struct{}{
	443:  {},
	4433: {},
	8443: {},
}

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
	if t.BlockQUIC && f.Proto == UDP {
		if _, ok := quicPorts[f.DstPort]; ok {
			return true
		}
	}
	if t.BlockEncryptedDNS {
		switch f.DstPort {
		case portDoQAlt, portEncryptedDS, portDNSCrypt, portDNSCryptAlt, portDoQAlt2:
			return true
		}
	}
	if t.BlockVPNPorts {
		if _, ok := vpnDefaultPorts[f.DstPort]; ok {
			return true
		}
	}
	return false
}
