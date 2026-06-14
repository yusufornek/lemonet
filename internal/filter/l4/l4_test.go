package l4

import (
	"testing"

	"github.com/yusufornek/lemonet/internal/filter/rules"
)

func TestBlocked(t *testing.T) {
	all := rules.Toggles{BlockQUIC: true, BlockEncryptedDNS: true, BlockVPNPorts: true}
	cases := []struct {
		name string
		t    rules.Toggles
		f    Flow
		want bool
	}{
		{"quic udp 443", all, Flow{UDP, 443}, true},
		{"quic udp 4433", all, Flow{UDP, 4433}, true},
		{"quic udp 8443", all, Flow{UDP, 8443}, true},
		{"tcp 443 stays", all, Flow{TCP, 443}, false},
		{"tcp alt quic port stays", all, Flow{TCP, 8443}, false},
		{"doq alternate tcp 784", all, Flow{TCP, 784}, true},
		{"doq alternate udp 784", all, Flow{UDP, 784}, true},
		{"dot 853", all, Flow{TCP, 853}, true},
		{"dnscrypt tcp 5353", all, Flow{TCP, 5353}, true},
		{"dnscrypt udp 5353", all, Flow{UDP, 5353}, true},
		{"dnscrypt alternate 5443", all, Flow{TCP, 5443}, true},
		{"doq alternate 8853", all, Flow{UDP, 8853}, true},
		{"wireguard default", all, Flow{UDP, 51820}, true},
		{"plain http", all, Flow{TCP, 80}, false},
		{"quic off", rules.Toggles{}, Flow{UDP, 443}, false},
	}
	for _, c := range cases {
		if got := Blocked(c.t, c.f); got != c.want {
			t.Errorf("%s: Blocked = %v, want %v", c.name, got, c.want)
		}
	}
}
