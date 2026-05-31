// Package filter is the content-filtering facade. It implements engine.FlowInspector by combining
// per-device policy with the transport (l4), DNS, and SNI decision layers.
package filter

import (
	"net/netip"
	"sync"

	"github.com/yusufornek/lemonet/internal/engine"
	"github.com/yusufornek/lemonet/internal/filter/dns"
	"github.com/yusufornek/lemonet/internal/filter/l4"
	"github.com/yusufornek/lemonet/internal/filter/rules"
	"github.com/yusufornek/lemonet/internal/filter/sni"
)

const (
	portDNS   = 53
	portHTTPS = 443
)

// Filter holds the shared rules engine and the per-device policies the relay consults.
type Filter struct {
	engine *rules.Engine

	mu       sync.RWMutex
	policies map[netip.Addr]rules.DevicePolicy
}

func New(engine *rules.Engine) *Filter {
	return &Filter{engine: engine, policies: make(map[netip.Addr]rules.DevicePolicy)}
}

func (f *Filter) SetPolicy(ip netip.Addr, p rules.DevicePolicy) {
	f.mu.Lock()
	f.policies[ip] = p
	f.mu.Unlock()
}

func (f *Filter) ClearPolicy(ip netip.Addr) {
	f.mu.Lock()
	delete(f.policies, ip)
	f.mu.Unlock()
}

func (f *Filter) ClearAll() {
	f.mu.Lock()
	f.policies = make(map[netip.Addr]rules.DevicePolicy)
	f.mu.Unlock()
}

// InspectFlow decides one flow. Order: transport toggles first (cheapest), then DNS query names,
// then plaintext TLS SNI. A device with no policy is never filtered.
func (f *Filter) InspectFlow(device netip.Addr, udp bool, dstPort uint16, payload []byte) bool {
	f.mu.RLock()
	pol, ok := f.policies[device]
	f.mu.RUnlock()
	if !ok {
		return false
	}

	proto := l4.TCP
	if udp {
		proto = l4.UDP
	}
	if l4.Blocked(pol.Toggles, l4.Flow{Proto: proto, DstPort: dstPort}) {
		return true
	}

	if udp && dstPort == portDNS {
		if q, ok := dns.ParseQuery(payload); ok {
			if pol.Toggles.FirefoxCanary && dns.IsFirefoxCanary(q.Name) {
				return true
			}
			if f.engine.DomainBlocked(pol, q.Name) {
				return true
			}
		}
	}

	if !udp && dstPort == portHTTPS && len(payload) > 0 {
		if host, ok := sni.Parse(payload); ok && f.engine.DomainBlocked(pol, host) {
			return true
		}
	}
	return false
}

var _ engine.FlowInspector = (*Filter)(nil)
