package dns

import (
	"testing"

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

func TestFirefoxCanary(t *testing.T) {
	if !IsFirefoxCanary("use-application-dns.net.") {
		t.Error("canary domain should be recognized")
	}
	if IsFirefoxCanary("example.com") {
		t.Error("normal domain is not the canary")
	}
}
