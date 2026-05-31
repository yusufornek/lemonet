// Package dns inspects and rewrites DNS messages passing through the gateway. It answers blocked
// queries with NXDOMAIN, and strips ECH parameters from HTTPS/SVCB answers so that a client falls
// back to a plaintext SNI that the sni package can read.
package dns

import (
	"strings"

	"github.com/miekg/dns"
)

// Query is the parsed first question of a DNS request.
type Query struct {
	Name string
	Type uint16
}

// ParseQuery extracts the first question from a DNS request payload.
func ParseQuery(payload []byte) (Query, bool) {
	var m dns.Msg
	if err := m.Unpack(payload); err != nil || len(m.Question) == 0 {
		return Query{}, false
	}
	q := m.Question[0]
	return Query{Name: strings.TrimSuffix(q.Name, "."), Type: q.Qtype}, true
}

// BuildRefusal answers a query with NXDOMAIN and an Extended DNS Error of "Filtered" (code 17),
// which tells the client the name was blocked by policy rather than failing silently.
func BuildRefusal(query []byte) ([]byte, error) {
	var req dns.Msg
	if err := req.Unpack(query); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.SetRcode(&req, dns.RcodeNameError)

	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeFiltered})
	resp.Extra = append(resp.Extra, opt)
	return resp.Pack()
}

// StripECH removes the ech parameter from HTTPS and SVCB answers. It reports whether anything
// changed so the caller can avoid re-sending an unmodified response.
func StripECH(response []byte) ([]byte, bool) {
	var m dns.Msg
	if err := m.Unpack(response); err != nil {
		return response, false
	}
	changed := false
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.HTTPS:
			if removeECH(&v.SVCB) {
				changed = true
			}
		case *dns.SVCB:
			if removeECH(v) {
				changed = true
			}
		}
	}
	if !changed {
		return response, false
	}
	packed, err := m.Pack()
	if err != nil {
		return response, false
	}
	return packed, true
}

func removeECH(svcb *dns.SVCB) bool {
	kept := svcb.Value[:0]
	removed := false
	for _, kv := range svcb.Value {
		if kv.Key() == dns.SVCB_ECHCONFIG {
			removed = true
			continue
		}
		kept = append(kept, kv)
	}
	svcb.Value = kept
	return removed
}

// IsFirefoxCanary reports whether name is the Firefox DoH canary domain. Returning NXDOMAIN for
// it makes Firefox disable its built-in DoH and fall back to the system resolver.
func IsFirefoxCanary(name string) bool {
	return strings.EqualFold(strings.TrimSuffix(name, "."), "use-application-dns.net")
}
