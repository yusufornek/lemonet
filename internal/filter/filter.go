// Package filter is the content-filtering facade. It implements engine.FlowInspector by combining
// per-device policy with the transport (l4), DNS, and SNI decision layers.
package filter

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/yusufornek/lemonet/internal/engine"
	"github.com/yusufornek/lemonet/internal/filter/dns"
	"github.com/yusufornek/lemonet/internal/filter/l4"
	"github.com/yusufornek/lemonet/internal/filter/rules"
	"github.com/yusufornek/lemonet/internal/filter/sni"
)

const (
	portDNS          = 53
	portHTTP         = 80
	portHTTPS        = 443
	portHTTPSAltQUIC = 4433
	portHTTPSAlt     = 8443

	httpsSessionFlushWindow = 2 * time.Minute
	blockedFlowWindow       = 5 * time.Minute
	allowedTLSFlowWindow    = 30 * time.Minute
	maxPendingTLSBytes      = 18 * 1024
)

// Filter holds the shared rules engine and the per-device policies the relay consults.
type Filter struct {
	engine *rules.Engine
	now    func() time.Time

	mu         sync.RWMutex
	policies   map[netip.Addr]rules.DevicePolicy
	flushUntil map[netip.Addr]time.Time
	blocked    map[blockedFlowKey]time.Time
	allowedTLS map[blockedFlowKey]time.Time
	blockedIPs map[blockedIPKey]time.Time
	pendingTLS map[blockedFlowKey][]byte
}

type blockedFlowKey struct {
	device      netip.Addr
	remote      netip.Addr
	udp         bool
	devicePort  uint16
	servicePort uint16
}

type blockedIPKey struct {
	device netip.Addr
	remote netip.Addr
}

func New(engine *rules.Engine) *Filter {
	return &Filter{
		engine:     engine,
		now:        time.Now,
		policies:   make(map[netip.Addr]rules.DevicePolicy),
		flushUntil: make(map[netip.Addr]time.Time),
		blocked:    make(map[blockedFlowKey]time.Time),
		allowedTLS: make(map[blockedFlowKey]time.Time),
		blockedIPs: make(map[blockedIPKey]time.Time),
		pendingTLS: make(map[blockedFlowKey][]byte),
	}
}

func (f *Filter) SetPolicy(ip netip.Addr, p rules.DevicePolicy) {
	f.mu.Lock()
	f.policies[ip] = p
	f.clearBlockedFlowsLocked(ip)
	f.clearBlockedIPsLocked(ip)
	if policyActive(p) {
		f.flushUntil[ip] = f.clock().Add(httpsSessionFlushWindow)
	} else {
		delete(f.flushUntil, ip)
	}
	f.mu.Unlock()
}

func (f *Filter) ClearPolicy(ip netip.Addr) {
	f.mu.Lock()
	delete(f.policies, ip)
	delete(f.flushUntil, ip)
	f.clearBlockedFlowsLocked(ip)
	f.clearBlockedIPsLocked(ip)
	f.mu.Unlock()
}

func (f *Filter) ClearAll() {
	f.mu.Lock()
	f.policies = make(map[netip.Addr]rules.DevicePolicy)
	f.flushUntil = make(map[netip.Addr]time.Time)
	f.blocked = make(map[blockedFlowKey]time.Time)
	f.allowedTLS = make(map[blockedFlowKey]time.Time)
	f.blockedIPs = make(map[blockedIPKey]time.Time)
	f.pendingTLS = make(map[blockedFlowKey][]byte)
	f.mu.Unlock()
}

// InspectFlow decides one flow. Order: transport toggles first (cheapest), then DNS query names,
// plaintext HTTP/TLS names, and finally a drain window for pre-existing HTTPS sessions.
func (f *Filter) InspectFlow(device netip.Addr, dir engine.Direction, udp bool, srcPort, dstPort uint16, payload []byte) engine.FlowAction {
	return f.InspectFlowContext(engine.FlowContext{
		Device:    device,
		Direction: dir,
		UDP:       udp,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Payload:   payload,
	})
}

func (f *Filter) InspectFlowContext(ctx engine.FlowContext) engine.FlowAction {
	f.mu.RLock()
	pol, ok := f.policies[ctx.Device]
	f.mu.RUnlock()
	if !ok {
		return engine.FlowAction{}
	}
	if f.blockedIP(ctx) {
		return f.dropFlow(ctx)
	}
	if f.blockedFlow(ctx) {
		return engine.FlowAction{Kind: engine.FlowDrop}
	}

	proto := l4.TCP
	if ctx.UDP {
		proto = l4.UDP
	}
	servicePort := ctx.DstPort
	if ctx.Direction == engine.Download {
		servicePort = ctx.SrcPort
	}
	if pol.Toggles.BlockEncryptedDNS && encryptedDNSServicePort(servicePort) {
		if remote, ok := remoteAddr(ctx); ok && knownEncryptedDNSResolver(remote) {
			f.rememberBlockedRemote(ctx, blockedFlowWindow)
			return f.dropFlow(ctx)
		}
	}
	if l4.Blocked(pol.Toggles, l4.Flow{Proto: proto, DstPort: servicePort}) {
		if !quicFallbackPort(ctx.UDP, servicePort) {
			f.rememberBlockedRemote(ctx, blockedFlowWindow)
		}
		return f.dropFlow(ctx)
	}

	if ctx.UDP && ctx.Direction == engine.Upload && ctx.DstPort == portDNS {
		if q, ok := dns.ParseQuery(ctx.Payload); ok {
			if pol.Toggles.FirefoxCanary && dns.IsFirefoxCanary(q.Name) {
				return dnsBlockAction(ctx.Payload)
			}
			if f.engine.DomainBlocked(pol, q.Name) {
				return dnsBlockAction(ctx.Payload)
			}
		}
	}

	if !ctx.UDP && ctx.Direction == engine.Upload && ctx.DstPort == portDNS {
		if name, ok := tcpDNSQueryName(ctx.Payload); ok {
			if pol.Toggles.FirefoxCanary && dns.IsFirefoxCanary(name) {
				return f.dropFlow(ctx)
			}
			if f.engine.DomainBlocked(pol, name) {
				return f.dropFlow(ctx)
			}
		}
	}

	if ctx.Direction == engine.Download && ctx.SrcPort == portDNS {
		if resp, ok := parseDNSResponsePayload(ctx); ok && f.dnsResponseBlocked(pol, resp) {
			f.rememberBlockedIPs(ctx.Device, resp.IPs, resp.IPTTL)
			replacement, err := dns.BuildRefusalFromResponse(ctx.Payload)
			if err != nil || !ctx.UDP {
				return f.dropFlow(ctx)
			}
			return engine.FlowAction{Kind: engine.FlowReplace, Payload: replacement}
		}
	}

	if !ctx.UDP && ctx.Direction == engine.Download && ctx.SrcPort == portDNS && pol.Toggles.StripECH {
		if payload, ok := tcpDNSPayload(ctx.Payload); ok {
			if _, changed := dns.StripECH(payload); changed {
				return f.dropFlow(ctx)
			}
		}
	}

	if ctx.UDP && ctx.Direction == engine.Download && ctx.SrcPort == portDNS && pol.Toggles.StripECH {
		if replacement, changed := dns.StripECH(ctx.Payload); changed {
			return engine.FlowAction{Kind: engine.FlowReplace, Payload: replacement}
		}
	}

	if !ctx.UDP && ctx.Direction == engine.Upload {
		if host, ok := httpHost(ctx.Payload); ok && f.engine.DomainBlocked(pol, host) {
			f.rememberBlockedRemote(ctx, blockedFlowWindow)
			return f.dropFlow(ctx)
		}
	}

	if !ctx.UDP && ctx.Direction == engine.Upload && len(ctx.Payload) > 0 {
		if action, handled := f.inspectTLSClientHello(ctx, pol); handled {
			return action
		}
	}
	if opaqueTLSRecordPayload(ctx.UDP, ctx.Payload) && tlsInspectionActive(pol) {
		if f.allowedTLSFlow(ctx) {
			return engine.FlowAction{}
		}
		f.rememberBlockedRemote(ctx, blockedFlowWindow)
		return f.dropFlow(ctx)
	}
	if !ctx.UDP && len(ctx.Payload) > 0 && tlsInspectionActive(pol) && likelyTLSServicePort(servicePort) && !sni.IsClientHello(ctx.Payload) {
		if f.allowedTLSFlow(ctx) {
			return engine.FlowAction{}
		}
		f.rememberBlockedRemote(ctx, blockedFlowWindow)
		return f.dropFlow(ctx)
	}
	return engine.FlowAction{}
}

func dnsBlockAction(payload []byte) engine.FlowAction {
	reply, err := dns.BuildRefusal(payload)
	if err != nil {
		return engine.FlowAction{Kind: engine.FlowDrop}
	}
	return engine.FlowAction{Kind: engine.FlowReply, Payload: reply}
}

func tcpDNSQueryName(payload []byte) (string, bool) {
	msg, ok := tcpDNSPayload(payload)
	if !ok {
		return "", false
	}
	q, ok := dns.ParseQuery(msg)
	if !ok {
		return "", false
	}
	return q.Name, true
}

func tcpDNSPayload(payload []byte) ([]byte, bool) {
	if len(payload) < 2 {
		return nil, false
	}
	size := int(binary.BigEndian.Uint16(payload[:2]))
	if size == 0 || len(payload)-2 < size {
		return nil, false
	}
	return payload[2 : 2+size], true
}

func parseDNSResponsePayload(ctx engine.FlowContext) (dns.Response, bool) {
	if ctx.UDP {
		return dns.ParseResponse(ctx.Payload)
	}
	msg, ok := tcpDNSPayload(ctx.Payload)
	if !ok {
		return dns.Response{}, false
	}
	return dns.ParseResponse(msg)
}

func httpHost(payload []byte) (string, bool) {
	if len(payload) == 0 {
		return "", false
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(payload)))
	if err != nil {
		return "", false
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	host := hostWithoutPort(req.Host)
	return host, host != ""
}

func (f *Filter) inspectTLSClientHello(ctx engine.FlowContext, pol rules.DevicePolicy) (engine.FlowAction, bool) {
	key, haveKey := flowKey(ctx)
	payload := ctx.Payload
	if haveKey {
		if pending, ok := f.pendingTLSPayload(key); ok {
			payload = append(pending, ctx.Payload...)
		}
	}

	if pol.Toggles.StripECH && sni.HasECH(payload) {
		if haveKey {
			f.clearPendingTLS(key)
		}
		f.rememberBlockedRemote(ctx, blockedFlowWindow)
		return f.dropFlow(ctx), true
	}
	if host, ok := sni.Parse(payload); ok {
		if haveKey {
			f.clearPendingTLS(key)
		}
		if f.engine.DomainBlocked(pol, host) {
			f.rememberBlockedRemote(ctx, blockedFlowWindow)
			return f.dropFlow(ctx), true
		}
		if haveKey {
			f.rememberAllowedTLSFlow(key)
		}
		return engine.FlowAction{}, true
	}
	if pol.Toggles.StripECH && sni.IsClientHello(payload) {
		if haveKey {
			f.clearPendingTLS(key)
		}
		f.rememberBlockedRemote(ctx, blockedFlowWindow)
		return f.dropFlow(ctx), true
	}
	if tlsInspectionActive(pol) && sni.IsIncompleteClientHello(payload) {
		if !haveKey {
			return engine.FlowAction{}, false
		}
		if len(payload) > maxPendingTLSBytes {
			f.clearPendingTLS(key)
			f.rememberBlockedRemote(ctx, blockedFlowWindow)
			return f.dropFlow(ctx), true
		}
		f.setPendingTLS(key, payload)
		return engine.FlowAction{}, true
	}
	if haveKey {
		f.clearPendingTLS(key)
	}
	return engine.FlowAction{}, false
}

func tlsInspectionActive(pol rules.DevicePolicy) bool {
	return len(pol.EnabledPacks) > 0 || len(pol.CustomRules) > 0 || pol.Toggles.StripECH
}

func likelyTLSServicePort(port uint16) bool {
	switch port {
	case portHTTPS, portHTTPSAltQUIC, portHTTPSAlt:
		return true
	default:
		return false
	}
}

func quicFallbackPort(udp bool, port uint16) bool {
	return udp && likelyTLSServicePort(port)
}

func (f *Filter) pendingTLSPayload(key blockedFlowKey) ([]byte, bool) {
	f.mu.RLock()
	payload, ok := f.pendingTLS[key]
	f.mu.RUnlock()
	if !ok {
		return nil, false
	}
	return append([]byte(nil), payload...), true
}

func (f *Filter) setPendingTLS(key blockedFlowKey, payload []byte) {
	f.mu.Lock()
	f.pendingTLS[key] = append([]byte(nil), payload...)
	f.mu.Unlock()
}

func (f *Filter) clearPendingTLS(key blockedFlowKey) {
	f.mu.Lock()
	delete(f.pendingTLS, key)
	f.mu.Unlock()
}

func hostWithoutPort(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return ""
	}
	if split, _, err := net.SplitHostPort(h); err == nil {
		return strings.Trim(split, "[]")
	}
	return strings.Trim(h, "[]")
}

func policyActive(p rules.DevicePolicy) bool {
	return len(p.EnabledPacks) > 0 || len(p.CustomRules) > 0 || p.Toggles != (rules.Toggles{})
}

func (f *Filter) dropFlow(ctx engine.FlowContext) engine.FlowAction {
	if key, ok := flowKey(ctx); ok {
		f.mu.Lock()
		f.blocked[key] = f.clock().Add(blockedFlowWindow)
		delete(f.allowedTLS, key)
		delete(f.pendingTLS, key)
		f.mu.Unlock()
	}
	return engine.FlowAction{Kind: engine.FlowDrop}
}

func (f *Filter) blockedFlow(ctx engine.FlowContext) bool {
	key, ok := flowKey(ctx)
	if !ok {
		return false
	}
	now := f.clock()
	f.mu.RLock()
	until, ok := f.blocked[key]
	f.mu.RUnlock()
	if !ok {
		return false
	}
	if now.Before(until) {
		f.mu.Lock()
		if current, ok := f.blocked[key]; ok && current.Equal(until) {
			f.blocked[key] = laterTime(current, now.Add(blockedFlowWindow))
		}
		f.mu.Unlock()
		return true
	}
	f.mu.Lock()
	if current, ok := f.blocked[key]; ok && current.Equal(until) {
		delete(f.blocked, key)
	}
	f.mu.Unlock()
	return false
}

func (f *Filter) rememberAllowedTLSFlow(key blockedFlowKey) {
	f.mu.Lock()
	f.allowedTLS[key] = f.clock().Add(allowedTLSFlowWindow)
	f.mu.Unlock()
}

func (f *Filter) allowedTLSFlow(ctx engine.FlowContext) bool {
	key, ok := flowKey(ctx)
	if !ok {
		return false
	}
	now := f.clock()
	f.mu.RLock()
	until, ok := f.allowedTLS[key]
	f.mu.RUnlock()
	if !ok {
		return false
	}
	if now.Before(until) {
		f.mu.Lock()
		if current, ok := f.allowedTLS[key]; ok && current.Equal(until) {
			f.allowedTLS[key] = laterTime(current, now.Add(allowedTLSFlowWindow))
		}
		f.mu.Unlock()
		return true
	}
	f.mu.Lock()
	if current, ok := f.allowedTLS[key]; ok && current.Equal(until) {
		delete(f.allowedTLS, key)
	}
	f.mu.Unlock()
	return false
}

func (f *Filter) blockedIP(ctx engine.FlowContext) bool {
	remote, ok := remoteAddr(ctx)
	if !ok {
		return false
	}
	key := blockedIPKey{device: ctx.Device, remote: remote}
	now := f.clock()
	f.mu.RLock()
	until, ok := f.blockedIPs[key]
	f.mu.RUnlock()
	if !ok {
		return false
	}
	if now.Before(until) {
		f.mu.Lock()
		if current, ok := f.blockedIPs[key]; ok && current.Equal(until) {
			f.blockedIPs[key] = laterTime(current, now.Add(blockedFlowWindow))
		}
		f.mu.Unlock()
		return true
	}
	f.mu.Lock()
	if current, ok := f.blockedIPs[key]; ok && current.Equal(until) {
		delete(f.blockedIPs, key)
	}
	f.mu.Unlock()
	return false
}

func flowKey(ctx engine.FlowContext) (blockedFlowKey, bool) {
	if !ctx.Device.IsValid() || !ctx.SrcIP.IsValid() || !ctx.DstIP.IsValid() {
		return blockedFlowKey{}, false
	}
	remote, ok := remoteAddr(ctx)
	if !ok {
		return blockedFlowKey{}, false
	}
	key := blockedFlowKey{device: ctx.Device, udp: ctx.UDP}
	if ctx.Direction == engine.Download {
		key.remote = remote
		key.servicePort = ctx.SrcPort
		key.devicePort = ctx.DstPort
	} else {
		key.remote = remote
		key.servicePort = ctx.DstPort
		key.devicePort = ctx.SrcPort
	}
	return key, true
}

func remoteAddr(ctx engine.FlowContext) (netip.Addr, bool) {
	if !ctx.Device.IsValid() || !ctx.SrcIP.IsValid() || !ctx.DstIP.IsValid() {
		return netip.Addr{}, false
	}
	if ctx.Direction == engine.Download {
		return ctx.SrcIP, true
	}
	return ctx.DstIP, true
}

func (f *Filter) dnsResponseBlocked(pol rules.DevicePolicy, resp dns.Response) bool {
	for _, name := range resp.Names {
		if f.engine.DomainBlocked(pol, name) {
			return true
		}
	}
	return false
}

func (f *Filter) rememberBlockedIPs(device netip.Addr, ips []netip.Addr, ttl time.Duration) {
	if !device.IsValid() || len(ips) == 0 {
		return
	}
	if ttl < blockedFlowWindow {
		ttl = blockedFlowWindow
	}
	until := f.clock().Add(ttl)
	f.mu.Lock()
	for _, ip := range ips {
		if ip.IsValid() {
			f.blockedIPs[blockedIPKey{device: device, remote: ip}] = until
		}
	}
	f.mu.Unlock()
}

func (f *Filter) rememberBlockedRemote(ctx engine.FlowContext, ttl time.Duration) {
	remote, ok := remoteAddr(ctx)
	if !ok {
		return
	}
	f.rememberBlockedIPs(ctx.Device, []netip.Addr{remote}, ttl)
}

func laterTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (f *Filter) clearBlockedFlowsLocked(device netip.Addr) {
	for key := range f.blocked {
		if key.device == device {
			delete(f.blocked, key)
		}
	}
	for key := range f.allowedTLS {
		if key.device == device {
			delete(f.allowedTLS, key)
		}
	}
	for key := range f.pendingTLS {
		if key.device == device {
			delete(f.pendingTLS, key)
		}
	}
}

func (f *Filter) clearBlockedIPsLocked(device netip.Addr) {
	for key := range f.blockedIPs {
		if key.device == device {
			delete(f.blockedIPs, key)
		}
	}
}

func opaqueTLSRecordPayload(udp bool, payload []byte) bool {
	if udp || len(payload) < 5 {
		return false
	}
	switch payload[0] {
	case 0x14, 0x15, 0x16, 0x17:
	default:
		return false
	}
	if payload[1] != 0x03 || payload[2] > 0x04 {
		return false
	}
	return !sni.IsClientHello(payload)
}

func (f *Filter) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

var _ engine.FlowInspector = (*Filter)(nil)
var _ engine.FlowContextInspector = (*Filter)(nil)
