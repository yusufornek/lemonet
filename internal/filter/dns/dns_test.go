package dns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseQuery(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("blocked.example.", dns.TypeA)
	packed, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	q, ok := ParseQuery(packed)
	if !ok {
		t.Fatal("expected to parse query")
	}
	if q.Name != "blocked.example" || q.Type != dns.TypeA {
		t.Errorf("got %+v", q)
	}
}

func TestBuildRefusalIsNXDOMAIN(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("blocked.example.", dns.TypeA)
	query, _ := m.Pack()

	resp, err := BuildRefusal(query)
	if err != nil {
		t.Fatal(err)
	}
	var parsed dns.Msg
	if err := parsed.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	if parsed.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %d, want NXDOMAIN", parsed.Rcode)
	}
	if parsed.IsEdns0() != nil {
		t.Error("plain DNS query should not receive EDNS options")
	}
}

func TestBuildRefusalKeepsEDNSFilteredCode(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("blocked.example.", dns.TypeA)
	m.SetEdns0(1232, false)
	query, _ := m.Pack()

	resp, err := BuildRefusal(query)
	if err != nil {
		t.Fatal(err)
	}
	var parsed dns.Msg
	if err := parsed.Unpack(resp); err != nil {
		t.Fatal(err)
	}
	opt := parsed.IsEdns0()
	if opt == nil {
		t.Fatal("EDNS query should receive an EDNS response")
	}
	for _, option := range opt.Option {
		if ede, ok := option.(*dns.EDNS0_EDE); ok && ede.InfoCode == dns.ExtendedErrorCodeFiltered {
			return
		}
	}
	t.Fatal("EDNS response should include EDE Filtered")
}

func TestBuildRefusalFromResponse(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("blocked.example.", dns.TypeA)
	req.SetEdns0(1232, false)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.SetEdns0(1232, false)
	resp.Answer = []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "blocked.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}},
	}
	payload, _ := resp.Pack()

	out, err := BuildRefusalFromResponse(payload)
	if err != nil {
		t.Fatal(err)
	}
	var parsed dns.Msg
	if err := parsed.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if !parsed.Response || parsed.Id != resp.Id || parsed.Rcode != dns.RcodeNameError || len(parsed.Answer) != 0 {
		t.Fatalf("response id/rcode/answers = %v/%d/%d", parsed.Response, parsed.Rcode, len(parsed.Answer))
	}
	if len(parsed.Question) != 1 || parsed.Question[0].Name != "blocked.example." {
		t.Fatalf("question = %+v", parsed.Question)
	}
	if parsed.IsEdns0() == nil {
		t.Fatal("filtered response should preserve EDNS metadata")
	}
}

func TestParseResponseNamesAndIPs(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("video.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "video.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "edge.example.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "edge.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{203, 0, 113, 20},
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "edge.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: netip.MustParseAddr("2001:db8::20").AsSlice(),
		},
	}
	payload, _ := resp.Pack()

	parsed, ok := ParseResponse(payload)
	if !ok {
		t.Fatal("expected DNS response to parse")
	}
	wantNames := map[string]bool{"video.example": true, "edge.example": true}
	for _, name := range parsed.Names {
		delete(wantNames, name)
	}
	if len(wantNames) != 0 {
		t.Fatalf("missing names: %+v from %+v", wantNames, parsed.Names)
	}
	wantIPs := map[netip.Addr]bool{
		netip.MustParseAddr("203.0.113.20"): true,
		netip.MustParseAddr("2001:db8::20"): true,
	}
	for _, ip := range parsed.IPs {
		delete(wantIPs, ip)
	}
	if len(wantIPs) != 0 {
		t.Fatalf("missing ips: %+v from %+v", wantIPs, parsed.IPs)
	}
}

func TestParseResponseIncludesHTTPSIPHints(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("video.example.", dns.TypeHTTPS)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: "video.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   ".",
			Value: []dns.SVCBKeyValue{
				&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("203.0.113.44")}},
				&dns.SVCBIPv6Hint{Hint: []net.IP{netip.MustParseAddr("2001:db8::44").AsSlice()}},
			},
		}},
	}
	payload, _ := resp.Pack()

	parsed, ok := ParseResponse(payload)
	if !ok {
		t.Fatal("expected DNS response to parse")
	}
	wantIPs := map[netip.Addr]bool{
		netip.MustParseAddr("203.0.113.44"): true,
		netip.MustParseAddr("2001:db8::44"): true,
	}
	for _, ip := range parsed.IPs {
		delete(wantIPs, ip)
	}
	if len(wantIPs) != 0 {
		t.Fatalf("missing hinted IPs: %+v from %+v", wantIPs, parsed.IPs)
	}
}

func TestParseResponseIncludesAdditionalIPs(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("video.example.", dns.TypeHTTPS)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.HTTPS{SVCB: dns.SVCB{
			Hdr:      dns.RR_Header{Name: "video.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
			Priority: 1,
			Target:   "edge.video.example.",
		}},
	}
	resp.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "edge.video.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{203, 0, 113, 45},
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "edge.video.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: netip.MustParseAddr("2001:db8::45").AsSlice(),
		},
	}
	payload, _ := resp.Pack()

	parsed, ok := ParseResponse(payload)
	if !ok {
		t.Fatal("expected DNS response to parse")
	}
	wantIPs := map[netip.Addr]bool{
		netip.MustParseAddr("203.0.113.45"): true,
		netip.MustParseAddr("2001:db8::45"): true,
	}
	for _, ip := range parsed.IPs {
		delete(wantIPs, ip)
	}
	if len(wantIPs) != 0 {
		t.Fatalf("missing additional IPs: %+v from %+v", wantIPs, parsed.IPs)
	}
}

func TestParseResponseTracksLongestIPTTL(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("video.example.", dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "video.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{203, 0, 113, 45},
		},
	}
	resp.Extra = []dns.RR{
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: "edge.video.example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1800},
			AAAA: netip.MustParseAddr("2001:db8::45").AsSlice(),
		},
	}
	payload, _ := resp.Pack()

	parsed, ok := ParseResponse(payload)
	if !ok {
		t.Fatal("expected DNS response to parse")
	}
	if parsed.IPTTL != 30*time.Minute {
		t.Fatalf("IPTTL = %s, want 30m", parsed.IPTTL)
	}
}

func TestStripECH(t *testing.T) {
	https := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
			&dns.SVCBECHConfig{ECH: []byte{0x01, 0x02, 0x03}},
		},
	}}
	resp := new(dns.Msg)
	resp.Answer = []dns.RR{https}
	packed, _ := resp.Pack()

	out, changed := StripECH(packed)
	if !changed {
		t.Fatal("expected ECH to be stripped")
	}
	var parsed dns.Msg
	if err := parsed.Unpack(out); err != nil {
		t.Fatal(err)
	}
	for _, kv := range parsed.Answer[0].(*dns.HTTPS).Value {
		if kv.Key() == dns.SVCB_ECHCONFIG {
			t.Error("ECH config should have been removed")
		}
	}
}

func TestStripECHFromAdditionalRecords(t *testing.T) {
	https := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "svc.example.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBECHConfig{ECH: []byte{0x01, 0x02, 0x03}},
		},
	}}
	resp := new(dns.Msg)
	resp.Extra = []dns.RR{https}
	packed, _ := resp.Pack()

	out, changed := StripECH(packed)
	if !changed {
		t.Fatal("expected ECH in additional records to be stripped")
	}
	var parsed dns.Msg
	if err := parsed.Unpack(out); err != nil {
		t.Fatal(err)
	}
	for _, kv := range parsed.Extra[0].(*dns.HTTPS).Value {
		if kv.Key() == dns.SVCB_ECHCONFIG {
			t.Fatal("ECH config in additional records should have been removed")
		}
	}
}

func TestFirefoxCanary(t *testing.T) {
	if !IsFirefoxCanary("use-application-dns.net.") {
		t.Error("canary domain should be recognized")
	}
	if IsFirefoxCanary("example.com") {
		t.Error("normal domain is not the canary")
	}
}
