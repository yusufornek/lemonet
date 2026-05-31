package filter

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"

	"github.com/yusufornek/lemonet/internal/filter/rules"
)

var device = netip.MustParseAddr("192.168.1.50")

func dnsQuery(name string) []byte {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	b, _ := m.Pack()
	return b
}

func newFilter() *Filter {
	e := rules.NewEngine()
	pack := &rules.ListPack{ID: "ads", Category: rules.CategoryAds}
	pack.Domains().Add("bad.test")
	e.AddPack(pack)

	f := New(e)
	f.SetPolicy(device, rules.DevicePolicy{
		EnabledPacks: []string{"ads"},
		Toggles:      rules.Toggles{BlockQUIC: true, FirefoxCanary: true},
	})
	return f
}

func TestInspectDNSBlock(t *testing.T) {
	f := newFilter()
	if !f.InspectFlow(device, true, 53, dnsQuery("tracker.bad.test")) {
		t.Error("blocked domain query should drop")
	}
	if f.InspectFlow(device, true, 53, dnsQuery("good.test")) {
		t.Error("allowed domain query should pass")
	}
}

func TestInspectQUIC(t *testing.T) {
	f := newFilter()
	if !f.InspectFlow(device, true, 443, nil) {
		t.Error("QUIC should be dropped when BlockQUIC is on")
	}
}

func TestInspectFirefoxCanary(t *testing.T) {
	f := newFilter()
	if !f.InspectFlow(device, true, 53, dnsQuery("use-application-dns.net")) {
		t.Error("Firefox canary should drop")
	}
}

func TestUnmanagedDevicePasses(t *testing.T) {
	f := newFilter()
	other := netip.MustParseAddr("192.168.1.99")
	if f.InspectFlow(other, true, 53, dnsQuery("tracker.bad.test")) {
		t.Error("device without policy must not be filtered")
	}
}
