package filter

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/yusufornek/lemonet/internal/engine"
	"github.com/yusufornek/lemonet/internal/filter/rules"
)

var device = netip.MustParseAddr("192.168.1.50")

func dnsQuery(name string) []byte {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	b, _ := m.Pack()
	return b
}

func tcpDNSQuery(name string) []byte {
	query := dnsQuery(name)
	out := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(out[:2], uint16(len(query)))
	copy(out[2:], query)
	return out
}

func tcpDNSResponse(t *testing.T, name, ip string) []byte {
	t.Helper()
	response := dnsResponsePayload(t, name, ip)
	return tcpDNSMessage(response)
}

func tcpDNSMessage(response []byte) []byte {
	out := make([]byte, len(response)+2)
	binary.BigEndian.PutUint16(out[:2], uint16(len(response)))
	copy(out[2:], response)
	return out
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
	action := f.InspectFlow(device, engine.Upload, true, 53123, 53, dnsQuery("tracker.bad.test"))
	if action.Kind != engine.FlowReply || len(action.Payload) == 0 {
		t.Error("blocked domain query should drop")
	}
	action = f.InspectFlow(device, engine.Upload, true, 53123, 53, dnsQuery("good.test"))
	if action.Kind != engine.FlowAllow || len(action.Payload) != 0 {
		t.Error("allowed domain query should pass")
	}
}

func TestInspectTCPDNSBlock(t *testing.T) {
	f := newFilter()
	action := f.InspectFlow(device, engine.Upload, false, 53123, 53, tcpDNSQuery("tracker.bad.test"))
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked TCP DNS query should drop, got %+v", action)
	}
	action = f.InspectFlow(device, engine.Upload, false, 53123, 53, tcpDNSQuery("good.test"))
	if action.Kind != engine.FlowAllow {
		t.Fatalf("allowed TCP DNS query should pass, got %+v", action)
	}
}

func TestInspectHTTPHostBlock(t *testing.T) {
	f := newFilter()
	request := []byte("GET /watch HTTP/1.1\r\nHost: tracker.bad.test\r\nUser-Agent: test\r\n\r\n")
	action := f.InspectFlow(device, engine.Upload, false, 53123, 80, request)
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTP host should drop, got %+v", action)
	}
	allowed := []byte("GET / HTTP/1.1\r\nHost: good.test\r\n\r\n")
	action = f.InspectFlow(device, engine.Upload, false, 53123, 80, allowed)
	if action.Kind != engine.FlowAllow {
		t.Fatalf("allowed HTTP host should pass, got %+v", action)
	}
}

func TestInspectHTTPHostBlockOnNonStandardPort(t *testing.T) {
	f := newFilter()
	request := []byte("GET /api HTTP/1.1\r\nHost: tracker.bad.test\r\n\r\n")

	action := f.InspectFlow(device, engine.Upload, false, 53123, 8080, request)
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTP host on a non-standard port should drop, got %+v", action)
	}
}

func TestInspectHTTPHostBlockWithExplicitPort(t *testing.T) {
	f := newFilter()
	request := []byte("GET /api HTTP/1.1\r\nHost: tracker.bad.test:8080\r\n\r\n")

	action := f.InspectFlow(device, engine.Upload, false, 53123, 8080, request)
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTP host with explicit port should drop, got %+v", action)
	}
}

func TestInspectRemembersRemoteIPFromBlockedHTTPHost(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.87")
	request := []byte("GET /api HTTP/1.1\r\nHost: tracker.bad.test\r\n\r\n")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   80,
		Payload:   request,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTP host should drop, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new flow to HTTP-learned blocked IP should drop before payload inspection, got %+v", action)
	}
}

func TestInspectKeepsUnknownHTTPSPayloadBlockedAfterPolicyChange(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})

	action := f.InspectFlow(device, engine.Download, false, 443, 53123, []byte{0x17, 0x03, 0x03, 0x00, 0x20})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("unknown HTTPS payload should be dropped during the session flush, got %+v", action)
	}

	now = now.Add(httpsSessionFlushWindow + time.Second)
	action = f.InspectFlow(device, engine.Download, false, 443, 53123, []byte{0x17, 0x03, 0x03, 0x00, 0x20})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("unknown HTTPS payload should stay blocked until an allowed handshake is observed, got %+v", action)
	}
}

func TestInspectRequiresAllowedTLSClientHelloBeforeTLSApplicationData(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	remote := netip.MustParseAddr("203.0.113.82")
	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("unobserved TLS application-data should stay blocked while domain filtering is active, got %+v", action)
	}

	allowedRemote := netip.MustParseAddr("203.0.113.182")
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     allowedRemote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   captureTLSClientHello(t, "good.test"),
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("allowed TLS ClientHello should pass, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     allowedRemote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53124,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("TLS application-data for an observed allowed flow should pass, got %+v", action)
	}
}

func TestInspectRequiresAllowedTLSClientHelloBeforeTLSControlRecords(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     netip.MustParseAddr("203.0.113.83"),
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("unobserved TLS control record should stay blocked while domain filtering is active, got %+v", action)
	}
}

func TestInspectKeepsDrainingIdlePreExistingHTTPSAfterShortFlush(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(9 * time.Second)

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     netip.MustParseAddr("203.0.113.80"),
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("idle pre-existing HTTPS should still drop after the short flush window, got %+v", action)
	}
}

func TestInspectDrainsTLSApplicationDataOnNonStandardPort(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(9 * time.Second)

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     netip.MustParseAddr("203.0.113.81"),
		DstIP:     device,
		SrcPort:   8443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("pre-existing TLS application-data on a non-standard port should drop, got %+v", action)
	}
}

func TestInspectDropsUnclassifiedHTTPSPayloadUntilAllowedHandshake(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	remote := netip.MustParseAddr("203.0.113.84")
	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x8d, 0x14, 0x39, 0xa2, 0x01},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("unclassified HTTPS payload should drop until an allowed handshake is observed, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x01, 0x02, 0x03},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("remembered unclassified HTTPS flow should keep dropping, got %+v", action)
	}

	allowed := netip.MustParseAddr("203.0.113.85")
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     allowed,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   captureTLSClientHello(t, "good.test"),
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("allowed TLS ClientHello should pass, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     allowed,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53124,
		Payload:   []byte{0x8d, 0x14, 0x39, 0xa2, 0x01},
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("unclassified payload for an observed allowed TLS flow should pass, got %+v", action)
	}
}

func TestInspectRemembersRemoteIPFromUnclassifiedHTTPSPayload(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)
	remote := netip.MustParseAddr("203.0.113.88")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x8d, 0x14, 0x39, 0xa2, 0x01},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("unclassified HTTPS payload should drop, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new flow to unclassified HTTPS remote IP should drop before payload inspection, got %+v", action)
	}
}

func TestInspectRemembersRemoteIPFromOpaqueTLSRecord(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)
	remote := netip.MustParseAddr("203.0.113.89")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("opaque TLS record should drop, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new flow to opaque TLS remote IP should drop before payload inspection, got %+v", action)
	}
}

func TestInspectAllowsReadableHTTPSDuringPolicyFlush(t *testing.T) {
	f := newFilter()
	hello := captureTLSClientHello(t, "good.test")

	action := f.InspectFlow(device, engine.Upload, false, 53123, 443, hello)
	if action.Kind != engine.FlowAllow {
		t.Fatalf("readable allowed HTTPS ClientHello should pass during the session flush, got %+v", action)
	}
}

func TestInspectDropsNoSNITLSClientHelloWhenECHStrippingIsEnabled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{
		EnabledPacks: []string{"ads"},
		Toggles:      rules.Toggles{StripECH: true},
	})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     netip.MustParseAddr("203.0.113.40"),
		SrcPort:   53123,
		DstPort:   443,
		Payload:   captureTLSClientHello(t, ""),
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("no-SNI TLS ClientHello should drop when ECH stripping is enabled, got %+v", action)
	}
}

func TestInspectRemembersRemoteIPFromNoSNITLSClientHello(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{
		EnabledPacks: []string{"ads"},
		Toggles:      rules.Toggles{StripECH: true},
	})
	now = now.Add(httpsSessionFlushWindow + time.Second)
	remote := netip.MustParseAddr("203.0.113.42")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   captureTLSClientHello(t, ""),
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("no-SNI TLS ClientHello should drop when ECH stripping is enabled, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new flow to no-SNI remote IP should drop before payload inspection, got %+v", action)
	}
}

func TestInspectDropsECHClientHelloWhenECHStrippingIsEnabled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{
		EnabledPacks: []string{"ads"},
		Toggles:      rules.Toggles{StripECH: true},
	})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	hello := clientHelloWithExtension(t, captureTLSClientHello(t, "cover.example.com"), 0xfe0d, []byte{0x01, 0x02})
	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     netip.MustParseAddr("203.0.113.41"),
		SrcPort:   53123,
		DstPort:   443,
		Payload:   hello,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("ECH TLS ClientHello should drop when ECH stripping is enabled, got %+v", action)
	}
}

func TestInspectRemembersRemoteIPFromECHClientHello(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{
		EnabledPacks: []string{"ads"},
		Toggles:      rules.Toggles{StripECH: true},
	})
	now = now.Add(httpsSessionFlushWindow + time.Second)
	remote := netip.MustParseAddr("203.0.113.43")

	hello := clientHelloWithExtension(t, captureTLSClientHello(t, "cover.example.com"), 0xfe0d, []byte{0x01, 0x02})
	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   hello,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("ECH TLS ClientHello should drop when ECH stripping is enabled, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new flow to ECH remote IP should drop before payload inspection, got %+v", action)
	}
}

func TestInspectAllowsNoSNITLSClientHelloWhenECHStrippingIsDisabled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     netip.MustParseAddr("203.0.113.40"),
		SrcPort:   53123,
		DstPort:   443,
		Payload:   captureTLSClientHello(t, ""),
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("no-SNI TLS ClientHello should pass without ECH stripping, got %+v", action)
	}
}

func TestInspectBlocksReadableHTTPSDomain(t *testing.T) {
	f := newFilter()
	hello := captureTLSClientHello(t, "tracker.bad.test")

	action := f.InspectFlow(device, engine.Upload, false, 53123, 443, hello)
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTPS ClientHello should drop, got %+v", action)
	}
}

func TestInspectBlocksSplitHTTPSClientHello(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	e := rules.NewEngine()
	pack := &rules.ListPack{ID: "ads", Category: rules.CategoryAds}
	pack.Domains().Add("bad.test")
	e.AddPack(pack)
	f := New(e)
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	remote := netip.MustParseAddr("203.0.113.22")
	hello := captureTLSClientHello(t, "tracker.bad.test")
	first := hello[:11]
	second := hello[11:]

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   first,
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("first split ClientHello packet should pass until the host is readable, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   second,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("second split ClientHello packet should drop once the blocked host is readable, got %+v", action)
	}
}

func TestInspectAllowsSplitHTTPSClientHelloForAllowedHost(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	remote := netip.MustParseAddr("203.0.113.23")
	hello := captureTLSClientHello(t, "good.test")
	first := hello[:11]
	second := hello[11:]

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   first,
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("first split allowed ClientHello packet should pass, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   second,
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("second split allowed ClientHello packet should pass, got %+v", action)
	}
}

func TestInspectRemembersRemoteIPFromOversizedSplitTLSClientHello(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	remote := netip.MustParseAddr("203.0.113.25")
	first := []byte{0x16, 0x03, 0x03, 0xff, 0xff, 0x01}
	oversized := bytes.Repeat([]byte{0}, maxPendingTLSBytes)

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   first,
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("first split ClientHello packet should pass until the host is readable, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   oversized,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("oversized split ClientHello should drop, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new flow to oversized split TLS remote IP should drop before payload inspection, got %+v", action)
	}
}

func TestInspectDropsSplitNoSNITLSClientHelloWhenECHStrippingIsEnabled(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{
		EnabledPacks: []string{"ads"},
		Toggles:      rules.Toggles{StripECH: true},
	})
	now = now.Add(httpsSessionFlushWindow + time.Second)

	remote := netip.MustParseAddr("203.0.113.24")
	hello := captureTLSClientHello(t, "")
	first := hello[:11]
	second := hello[11:]

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   first,
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("first split no-SNI ClientHello packet should pass until complete, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   second,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("second split no-SNI ClientHello packet should drop when ECH stripping is enabled, got %+v", action)
	}
}

func TestInspectBlocksReadableHTTPSDomainOnNonStandardPort(t *testing.T) {
	f := newFilter()
	hello := captureTLSClientHello(t, "tracker.bad.test")

	action := f.InspectFlow(device, engine.Upload, false, 53123, 8443, hello)
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTPS ClientHello on a non-standard port should drop, got %+v", action)
	}
}

func TestInspectRemembersBlockedHTTPSFlowTuple(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.20")
	hello := captureTLSClientHello(t, "tracker.bad.test")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		UDP:       false,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   hello,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTPS ClientHello should drop, got %+v", action)
	}

	now = now.Add(httpsSessionFlushWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       false,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("remembered blocked HTTPS flow should keep dropping after flush, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       false,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53124,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("different unobserved HTTPS flow tuple should stay blocked, got %+v", action)
	}
}

func TestInspectRemembersRemoteIPFromBlockedSNI(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.86")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   captureTLSClientHello(t, "tracker.bad.test"),
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked SNI should drop, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new flow to SNI-learned blocked IP should drop before payload inspection, got %+v", action)
	}
}

func TestInspectRefreshesRememberedBlockedFlowOnHit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.20")
	hello := captureTLSClientHello(t, "tracker.bad.test")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   hello,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTPS ClientHello should drop, got %+v", action)
	}

	now = now.Add(blockedFlowWindow - time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("remembered blocked flow should drop near expiry, got %+v", action)
	}

	now = now.Add(2 * time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("recently seen blocked flow should extend its drop window, got %+v", action)
	}
}

func TestInspectClearsRememberedFlowsWithPolicy(t *testing.T) {
	f := newFilter()
	remote := netip.MustParseAddr("203.0.113.20")
	hello := captureTLSClientHello(t, "tracker.bad.test")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
		Payload:   hello,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked HTTPS ClientHello should drop, got %+v", action)
	}

	f.ClearPolicy(device)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		SrcIP:     remote,
		DstIP:     device,
		SrcPort:   443,
		DstPort:   53123,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("cleared policy should clear remembered flow drops, got %+v", action)
	}
}

func TestInspectQUIC(t *testing.T) {
	f := newFilter()
	if f.InspectFlow(device, engine.Upload, true, 53123, 443, nil).Kind != engine.FlowDrop {
		t.Error("QUIC should be dropped when BlockQUIC is on")
	}
	if f.InspectFlow(device, engine.Download, true, 443, 53123, nil).Kind != engine.FlowDrop {
		t.Error("QUIC download packets should also be dropped when BlockQUIC is on")
	}
}

func TestInspectDropsRepeatedQUICWithoutPoisoningTCPFallback(t *testing.T) {
	f := newFilter()
	remote := netip.MustParseAddr("203.0.113.91")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		UDP:       true,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("QUIC should drop when BlockQUIC is on, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		UDP:       true,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   4433,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("new QUIC flow to another QUIC port should drop, got %+v", action)
	}
}

func TestInspectAllowsTCPFallbackAfterBlockedQUIC(t *testing.T) {
	f := newFilter()
	remote := netip.MustParseAddr("203.0.113.92")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		UDP:       true,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53123,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("QUIC should drop when BlockQUIC is on, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   captureTLSClientHello(t, "good.test"),
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("allowed TCP fallback after blocked QUIC should pass for SNI inspection, got %+v", action)
	}
}

func TestInspectAlternativeQUICPorts(t *testing.T) {
	f := newFilter()
	if f.InspectFlow(device, engine.Upload, true, 53123, 4433, nil).Kind != engine.FlowDrop {
		t.Fatal("QUIC on UDP/4433 should be dropped when BlockQUIC is on")
	}
	if f.InspectFlow(device, engine.Download, true, 8443, 53123, nil).Kind != engine.FlowDrop {
		t.Fatal("QUIC download packets from UDP/8443 should be dropped when BlockQUIC is on")
	}
}

func TestInspectBlocksKnownEncryptedDNSResolverIPOverHTTPS(t *testing.T) {
	e := rules.NewEngine()
	f := New(e)
	f.SetPolicy(device, rules.DevicePolicy{Toggles: rules.Toggles{BlockEncryptedDNS: true}})

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     netip.MustParseAddr("8.8.8.8"),
		SrcPort:   53123,
		DstPort:   443,
		Payload:   []byte{0x16, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("known DoH resolver IP over HTTPS should drop, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     netip.MustParseAddr("203.0.113.90"),
		SrcPort:   53124,
		DstPort:   443,
		Payload:   []byte{0x16, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("ordinary HTTPS IP should pass when only encrypted DNS blocking is enabled, got %+v", action)
	}
}

func TestInspectBlocksKnownEncryptedDNSResolverRangeOverHTTPS(t *testing.T) {
	e := rules.NewEngine()
	f := New(e)
	f.SetPolicy(device, rules.DevicePolicy{Toggles: rules.Toggles{BlockEncryptedDNS: true}})

	for _, remote := range []string{
		"104.16.248.249",
		"104.16.249.249",
		"1.1.1.2",
		"1.0.0.2",
		"1.1.1.3",
		"1.0.0.3",
		"9.9.9.10",
		"9.9.9.11",
		"149.112.112.9",
		"149.112.112.10",
		"149.112.112.11",
		"146.112.41.2",
		"146.112.41.3",
		"162.159.61.4",
		"172.64.41.4",
		"185.228.168.10",
		"185.228.168.168",
		"45.90.28.17",
		"45.90.30.99",
		"94.140.14.140",
		"94.140.14.141",
		"194.242.2.4",
		"194.242.2.5",
		"194.242.2.6",
		"194.242.2.9",
		"76.76.2.44",
		"76.76.10.11",
		"2606:4700:4700::1112",
		"2606:4700:4700::1002",
		"2606:4700:4700::1113",
		"2606:4700:4700::1003",
		"2620:fe::10",
		"2620:fe::11",
		"2620:fe::fe:9",
		"2620:fe::fe:10",
		"2620:fe::fe:11",
		"2620:119:fc::2",
		"2620:119:fc::3",
		"2606:4700::6810:f8f9",
		"2606:4700::6810:f9f9",
		"2803:f800:53::4",
		"2a06:98c1:52::4",
		"2a07:a8c0::1234",
		"2a07:a8c1::1234",
		"2a10:50c0::1:ff",
		"2a10:50c0::2:ff",
		"2a07:e340::4",
		"2a07:e340::5",
		"2a07:e340::6",
		"2a07:e340::9",
		"2606:1a40::1234",
		"2606:1a40:1::1234",
	} {
		action := f.InspectFlowContext(engine.FlowContext{
			Device:    device,
			Direction: engine.Upload,
			SrcIP:     device,
			DstIP:     netip.MustParseAddr(remote),
			SrcPort:   53123,
			DstPort:   443,
		})
		if action.Kind != engine.FlowDrop {
			t.Fatalf("known encrypted DNS resolver range IP %s over HTTPS should drop, got %+v", remote, action)
		}
	}
}

func TestInspectBlocksKnownEncryptedDNSResolverIPv6OverHTTPS(t *testing.T) {
	e := rules.NewEngine()
	f := New(e)
	f.SetPolicy(device, rules.DevicePolicy{Toggles: rules.Toggles{BlockEncryptedDNS: true}})

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     netip.MustParseAddr("2001:db8::50"),
		DstIP:     netip.MustParseAddr("2001:4860:4860::8888"),
		SrcPort:   53123,
		DstPort:   443,
		Payload:   []byte{0x16, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("known IPv6 DoH resolver over HTTPS should drop, got %+v", action)
	}
}

func TestInspectBlocksKnownEncryptedDNSResolverAlternatePorts(t *testing.T) {
	e := rules.NewEngine()
	f := New(e)
	f.SetPolicy(device, rules.DevicePolicy{Toggles: rules.Toggles{BlockEncryptedDNS: true}})

	for _, port := range []uint16{784, 5353, 5443, 8443, 8853} {
		action := f.InspectFlowContext(engine.FlowContext{
			Device:    device,
			Direction: engine.Upload,
			SrcIP:     device,
			DstIP:     netip.MustParseAddr("1.1.1.1"),
			SrcPort:   53123,
			DstPort:   port,
		})
		if action.Kind != engine.FlowDrop {
			t.Fatalf("known encrypted DNS resolver on port %d should drop, got %+v", port, action)
		}
	}

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     netip.MustParseAddr("203.0.113.91"),
		SrcPort:   53123,
		DstPort:   8443,
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("ordinary HTTPS alternate port should pass when only encrypted DNS blocking is enabled, got %+v", action)
	}
}

func TestInspectFirefoxCanary(t *testing.T) {
	f := newFilter()
	action := f.InspectFlow(device, engine.Upload, true, 53123, 53, dnsQuery("use-application-dns.net"))
	if action.Kind != engine.FlowReply || len(action.Payload) == 0 {
		t.Error("Firefox canary should drop")
	}
}

func TestInspectStripsECHFromDNSResponse(t *testing.T) {
	e := rules.NewEngine()
	f := New(e)
	f.SetPolicy(device, rules.DevicePolicy{Toggles: rules.Toggles{StripECH: true}})

	action := f.InspectFlow(device, engine.Download, true, 53, 53123, dnsHTTPSResponse(t, true))
	if action.Kind != engine.FlowReplace || len(action.Payload) == 0 {
		t.Fatalf("ECH response should be rewritten, got %+v", action)
	}
	var parsed dns.Msg
	if err := parsed.Unpack(action.Payload); err != nil {
		t.Fatal(err)
	}
	for _, kv := range parsed.Answer[0].(*dns.HTTPS).Value {
		if kv.Key() == dns.SVCB_ECHCONFIG {
			t.Fatal("ECH config should be stripped")
		}
	}
}

func TestInspectDropsTCPDNSResponseWithECH(t *testing.T) {
	e := rules.NewEngine()
	f := New(e)
	f.SetPolicy(device, rules.DevicePolicy{Toggles: rules.Toggles{StripECH: true}})

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       false,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   tcpDNSMessage(dnsHTTPSResponse(t, true)),
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("TCP DNS response with ECH should drop, got %+v", action)
	}

	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       false,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53124,
		Payload:   tcpDNSMessage(dnsHTTPSResponse(t, false)),
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("TCP DNS response without ECH should pass, got %+v", action)
	}
}

func TestInspectReplacesBlockedDNSResponseAndRemembersAnswerIPs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.20")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       true,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   dnsResponsePayload(t, "tracker.bad.test", remote.String()),
	})
	if action.Kind != engine.FlowReplace || len(action.Payload) == 0 {
		t.Fatalf("blocked DNS response should be replaced, got %+v", action)
	}
	var parsed dns.Msg
	if err := parsed.Unpack(action.Payload); err != nil {
		t.Fatal(err)
	}
	if parsed.Rcode != dns.RcodeNameError || len(parsed.Answer) != 0 {
		t.Fatalf("dns response rcode/answers = %d/%d, want NXDOMAIN with no answers", parsed.Rcode, len(parsed.Answer))
	}

	now = now.Add(httpsSessionFlushWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		UDP:       false,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("connection to IP learned from a blocked DNS response should drop, got %+v", action)
	}
}

func TestInspectReplacesBlockedDNSAAAAResponseAndRemembersIPv6Answer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("2001:db8::20")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       true,
		SrcIP:     netip.MustParseAddr("2001:4860:4860::8888"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   dnsAAAAResponsePayload(t, "tracker.bad.test", remote.String()),
	})
	if action.Kind != engine.FlowReplace || len(action.Payload) == 0 {
		t.Fatalf("blocked DNS AAAA response should be replaced, got %+v", action)
	}

	now = now.Add(httpsSessionFlushWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		UDP:       false,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("connection to IPv6 learned from a blocked DNS AAAA response should drop, got %+v", action)
	}
}

func TestInspectRefreshesRememberedBlockedIPOnHit(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.20")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       true,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   dnsResponsePayload(t, "tracker.bad.test", remote.String()),
	})
	if action.Kind != engine.FlowReplace || len(action.Payload) == 0 {
		t.Fatalf("blocked DNS response should be replaced, got %+v", action)
	}

	now = now.Add(blockedFlowWindow - time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("remembered blocked IP should drop near expiry, got %+v", action)
	}

	now = now.Add(2 * time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53125,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("recently seen blocked IP should extend its drop window, got %+v", action)
	}
}

func TestInspectKeepsDNSLearnedBlockedIPForResponseTTL(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.20")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       true,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   dnsResponsePayloadWithTTL(t, "tracker.bad.test", remote.String(), 1800),
	})
	if action.Kind != engine.FlowReplace || len(action.Payload) == 0 {
		t.Fatalf("blocked DNS response should be replaced, got %+v", action)
	}

	now = now.Add(blockedFlowWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("DNS-learned blocked IP should stay blocked for DNS TTL, got %+v", action)
	}

	now = now.Add(blockedFlowWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53125,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked IP hit should not shorten the DNS TTL retention window, got %+v", action)
	}
}

func TestInspectReplacesBlockedHTTPSDNSResponseAndRemembersHintIPs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.44")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       true,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   dnsHTTPSHintResponsePayload(t, "tracker.bad.test", remote.String()),
	})
	if action.Kind != engine.FlowReplace || len(action.Payload) == 0 {
		t.Fatalf("blocked HTTPS DNS response should be replaced, got %+v", action)
	}

	now = now.Add(httpsSessionFlushWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("connection to IP learned from a blocked HTTPS DNS hint should drop, got %+v", action)
	}
}

func TestInspectReplacesBlockedHTTPSDNSResponseAndRemembersAdditionalIPs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.45")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       true,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   dnsHTTPSAdditionalResponsePayload(t, "tracker.bad.test", "edge.bad.test", remote.String()),
	})
	if action.Kind != engine.FlowReplace || len(action.Payload) == 0 {
		t.Fatalf("blocked HTTPS DNS response should be replaced, got %+v", action)
	}

	now = now.Add(httpsSessionFlushWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("connection to IP learned from blocked DNS additional records should drop, got %+v", action)
	}
}

func TestInspectDropsTCPDNSResponseAndRemembersAnswerIPs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	f := newFilter()
	f.now = func() time.Time { return now }
	f.SetPolicy(device, rules.DevicePolicy{EnabledPacks: []string{"ads"}})
	remote := netip.MustParseAddr("203.0.113.21")

	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       false,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   tcpDNSResponse(t, "tracker.bad.test", remote.String()),
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("blocked TCP DNS response should be dropped, got %+v", action)
	}

	now = now.Add(httpsSessionFlushWindow + time.Second)
	action = f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Upload,
		SrcIP:     device,
		DstIP:     remote,
		SrcPort:   53124,
		DstPort:   443,
		Payload:   []byte{0x17, 0x03, 0x03, 0x00, 0x20},
	})
	if action.Kind != engine.FlowDrop {
		t.Fatalf("connection to IP learned from a blocked TCP DNS response should drop, got %+v", action)
	}
}

func TestInspectAllowsUnblockedDNSResponse(t *testing.T) {
	f := newFilter()
	action := f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: engine.Download,
		UDP:       true,
		SrcIP:     netip.MustParseAddr("8.8.8.8"),
		DstIP:     device,
		SrcPort:   53,
		DstPort:   53123,
		Payload:   dnsResponsePayload(t, "good.test", "203.0.113.30"),
	})
	if action.Kind != engine.FlowAllow {
		t.Fatalf("unblocked DNS response should pass, got %+v", action)
	}
}

func TestUnmanagedDevicePasses(t *testing.T) {
	f := newFilter()
	other := netip.MustParseAddr("192.168.1.99")
	if f.InspectFlow(other, engine.Upload, true, 53123, 53, dnsQuery("tracker.bad.test")).Kind != engine.FlowAllow {
		t.Error("device without policy must not be filtered")
	}
}

func captureTLSClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("reading ClientHello: %v", err)
	}
	return buf[:n]
}

func clientHelloWithExtension(t *testing.T, hello []byte, extType uint16, extData []byte) []byte {
	t.Helper()
	out := append([]byte(nil), hello...)
	if len(out) < 9 || out[0] != 0x16 || out[5] != 0x01 {
		t.Fatalf("input is not a TLS ClientHello record")
	}

	recordLen := int(binary.BigEndian.Uint16(out[3:5]))
	handshakeLen := int(out[6])<<16 | int(out[7])<<8 | int(out[8])
	if len(out) != 5+recordLen || recordLen != 4+handshakeLen {
		t.Fatalf("unexpected ClientHello record shape")
	}

	pos := 9
	pos += 2 + 32
	if pos >= len(out) {
		t.Fatalf("truncated ClientHello before session id")
	}
	sessionLen := int(out[pos])
	pos += 1 + sessionLen
	if pos+2 > len(out) {
		t.Fatalf("truncated ClientHello before cipher suites")
	}
	cipherLen := int(binary.BigEndian.Uint16(out[pos : pos+2]))
	pos += 2 + cipherLen
	if pos >= len(out) {
		t.Fatalf("truncated ClientHello before compression methods")
	}
	compressionLen := int(out[pos])
	pos += 1 + compressionLen
	if pos+2 > len(out) {
		t.Fatalf("truncated ClientHello before extensions")
	}

	extLenPos := pos
	extLen := int(binary.BigEndian.Uint16(out[extLenPos : extLenPos+2]))
	if extLenPos+2+extLen != len(out) {
		t.Fatalf("unexpected ClientHello extension block length")
	}

	extension := make([]byte, 4+len(extData))
	binary.BigEndian.PutUint16(extension[:2], extType)
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(extData)))
	copy(extension[4:], extData)

	recordLen += len(extension)
	handshakeLen += len(extension)
	extLen += len(extension)
	if recordLen > 0xffff || handshakeLen > 0xffffff || extLen > 0xffff {
		t.Fatalf("ClientHello extension would exceed TLS length fields")
	}

	out = append(out, extension...)
	binary.BigEndian.PutUint16(out[3:5], uint16(recordLen))
	out[6] = byte(handshakeLen >> 16)
	out[7] = byte(handshakeLen >> 8)
	out[8] = byte(handshakeLen)
	binary.BigEndian.PutUint16(out[extLenPos:extLenPos+2], uint16(extLen))
	return out
}

func dnsHTTPSResponse(t *testing.T, ech bool) []byte {
	t.Helper()
	https := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
		},
	}}
	if ech {
		https.Value = append(https.Value, &dns.SVCBECHConfig{ECH: []byte{0x01, 0x02}})
	}
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{https}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func dnsResponsePayload(t *testing.T, name, ip string) []byte {
	return dnsResponsePayloadWithTTL(t, name, ip, 300)
}

func dnsResponsePayloadWithTTL(t *testing.T, name, ip string, ttl uint32) []byte {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(ip),
		},
	}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func dnsAAAAResponsePayload(t *testing.T, name, ip string) []byte {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: netip.MustParseAddr(ip).AsSlice(),
		},
	}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func dnsHTTPSHintResponsePayload(t *testing.T, name, ip string) []byte {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeHTTPS)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(ip)}},
			},
		}},
	}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func dnsHTTPSAdditionalResponsePayload(t *testing.T, name, target, ip string) []byte {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), dns.TypeHTTPS)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   dns.Fqdn(target),
		}},
	}
	resp.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(target), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip),
		},
	}
	packed, err := resp.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}
