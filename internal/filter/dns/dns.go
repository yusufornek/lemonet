// Package dns inspects and rewrites DNS messages passing through the gateway. It answers blocked
// queries with NXDOMAIN, and strips ECH parameters from HTTPS/SVCB answers so that a client falls
// back to a plaintext SNI that the sni package can read.
package dns

import (
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Query is the parsed first question of a DNS request.
type Query struct {
	Name string
	Type uint16
}

type Response struct {
	Names []string
	IPs   []netip.Addr
	IPTTL time.Duration
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

	if req.IsEdns0() != nil {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeFiltered})
		resp.Extra = append(resp.Extra, opt)
	}
	return resp.Pack()
}

func BuildRefusalFromResponse(payload []byte) ([]byte, error) {
	var in dns.Msg
	if err := in.Unpack(payload); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.MsgHdr = dns.MsgHdr{
		Id:                 in.Id,
		Response:           true,
		RecursionDesired:   in.RecursionDesired,
		RecursionAvailable: in.RecursionAvailable,
		Rcode:              dns.RcodeNameError,
	}
	resp.Question = append([]dns.Question(nil), in.Question...)
	if in.IsEdns0() != nil {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeFiltered})
		resp.Extra = append(resp.Extra, opt)
	}
	return resp.Pack()
}

func ParseResponse(payload []byte) (Response, bool) {
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil || !msg.Response {
		return Response{}, false
	}
	out := Response{}
	for _, q := range msg.Question {
		out.Names = append(out.Names, cleanName(q.Name))
	}
	out = appendResourceRecords(out, msg.Answer)
	out = appendResourceRecords(out, msg.Ns)
	out = appendResourceRecords(out, msg.Extra)
	return out, len(out.Names) > 0 || len(out.IPs) > 0
}

// StripECH removes the ech parameter from HTTPS and SVCB answers. It reports whether anything
// changed so the caller can avoid re-sending an unmodified response.
func StripECH(response []byte) ([]byte, bool) {
	var m dns.Msg
	if err := m.Unpack(response); err != nil {
		return response, false
	}
	changed := stripECHRecords(m.Answer)
	changed = stripECHRecords(m.Ns) || changed
	changed = stripECHRecords(m.Extra) || changed
	if !changed {
		return response, false
	}
	packed, err := m.Pack()
	if err != nil {
		return response, false
	}
	return packed, true
}

func stripECHRecords(records []dns.RR) bool {
	changed := false
	for _, rr := range records {
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
	return changed
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

func cleanName(name string) string {
	return strings.TrimSuffix(name, ".")
}

func appendTarget(names []string, target string) []string {
	cleaned := cleanName(target)
	if cleaned == "" || cleaned == "." {
		return names
	}
	return append(names, cleaned)
}

func appendResourceRecords(out Response, records []dns.RR) Response {
	for _, rr := range records {
		out.Names = append(out.Names, cleanName(rr.Header().Name))
		switch v := rr.(type) {
		case *dns.A:
			if addr, ok := netip.AddrFromSlice(v.A.To4()); ok {
				out.IPs = append(out.IPs, addr)
				out.IPTTL = maxDuration(out.IPTTL, recordTTL(rr))
			}
		case *dns.AAAA:
			if addr, ok := netip.AddrFromSlice(v.AAAA.To16()); ok {
				out.IPs = append(out.IPs, addr)
				out.IPTTL = maxDuration(out.IPTTL, recordTTL(rr))
			}
		case *dns.CNAME:
			out.Names = append(out.Names, cleanName(v.Target))
		case *dns.HTTPS:
			out.Names = appendTarget(out.Names, v.Target)
			before := len(out.IPs)
			out.IPs = appendSVCBHintIPs(out.IPs, v.Value)
			if len(out.IPs) > before {
				out.IPTTL = maxDuration(out.IPTTL, recordTTL(rr))
			}
		case *dns.SVCB:
			out.Names = appendTarget(out.Names, v.Target)
			before := len(out.IPs)
			out.IPs = appendSVCBHintIPs(out.IPs, v.Value)
			if len(out.IPs) > before {
				out.IPTTL = maxDuration(out.IPTTL, recordTTL(rr))
			}
		}
	}
	return out
}

func recordTTL(rr dns.RR) time.Duration {
	return time.Duration(rr.Header().Ttl) * time.Second
}

func maxDuration(a, b time.Duration) time.Duration {
	if b > a {
		return b
	}
	return a
}

func appendSVCBHintIPs(ips []netip.Addr, values []dns.SVCBKeyValue) []netip.Addr {
	for _, value := range values {
		switch hint := value.(type) {
		case *dns.SVCBIPv4Hint:
			for _, ip := range hint.Hint {
				if addr, ok := netip.AddrFromSlice(ip.To4()); ok {
					ips = append(ips, addr)
				}
			}
		case *dns.SVCBIPv6Hint:
			for _, ip := range hint.Hint {
				if addr, ok := netip.AddrFromSlice(ip.To16()); ok {
					ips = append(ips, addr)
				}
			}
		}
	}
	return ips
}
