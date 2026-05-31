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
		{"tcp 443 stays", all, Flow{TCP, 443}, false},
		{"dot 853", all, Flow{TCP, 853}, true},
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
