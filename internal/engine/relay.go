package engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Direction is the side of a flow relative to a LAN device: traffic leaving it (Upload) or
// arriving for it (Download).
type Direction int

const (
	Upload Direction = iota
	Download
)

const (
	portDNS        = 53
	maxRelayEvents = 64
)

// Decider decides what the relay does with one intercepted packet. A nil Decider forwards
// everything unchanged. delay > 0 means hold the packet that long before forwarding (shaping);
// drop means discard it (block).
type Decider interface {
	Decide(device netip.Addr, dir Direction, length int) (drop bool, delay time.Duration)
}

// FlowInspector inspects a transport flow for content policy (blocked domains, QUIC, VPN ports).
// payload is the application data (a DNS message on UDP/53, a TLS record on TCP/443).
type FlowInspector interface {
	InspectFlow(device netip.Addr, dir Direction, udp bool, srcPort, dstPort uint16, payload []byte) FlowAction
}

type FlowContextInspector interface {
	InspectFlowContext(FlowContext) FlowAction
}

type FlowContext struct {
	Device    netip.Addr
	Direction Direction
	UDP       bool
	SrcIP     netip.Addr
	DstIP     netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Payload   []byte
}

type FlowActionKind int

const (
	FlowAllow FlowActionKind = iota
	FlowDrop
	FlowReply
	FlowReplace
)

type FlowAction struct {
	Kind    FlowActionKind
	Payload []byte
}

var serializeOptions = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

// Relay is the userspace forwarding path. Once targets are poisoned, their frames arrive at our
// MAC; the relay applies policy and re-injects them toward the real next hop. Forwarding in user
// space (rather than the kernel) is what lets the Decider shape and block traffic uniformly
// across platforms.
type Relay struct {
	handle      Handle
	iface       Interface
	gwIP        net.IP
	gwMAC       []byte
	table       *Table
	dec         Decider
	inspect     FlowInspector
	onV6Learned func()

	// Diagnostic counters (atomic): rx = intercepted frames routed (rx6 = the IPv6 subset),
	// fwd = forwarded, drop = blocked, delay = shaped. They reveal whether the relay is on the path.
	rx, rx6, fwd, drop, delay atomic.Uint64
	replies, rewrites         atomic.Uint64
	fragments, redirects      atomic.Uint64
	sendErrs                  atomic.Uint64

	mu       sync.Mutex
	byDevice map[netip.Addr]*relayDeviceCounters
	recent   []RelayEvent
}

type RelayStats struct {
	Received   uint64             `json:"received"`
	IPv6       uint64             `json:"ipv6"`
	Forwarded  uint64             `json:"forwarded"`
	Dropped    uint64             `json:"dropped"`
	Shaped     uint64             `json:"shaped"`
	Replies    uint64             `json:"replies"`
	Rewrites   uint64             `json:"rewrites"`
	Fragments  uint64             `json:"fragments"`
	Redirects  uint64             `json:"redirects"`
	SendErrors uint64             `json:"sendErrors"`
	Devices    []RelayDeviceStats `json:"devices"`
	Recent     []RelayEvent       `json:"recent"`
}

type RelayDeviceStats struct {
	Device     string `json:"device"`
	Received   uint64 `json:"received"`
	IPv6       uint64 `json:"ipv6"`
	Forwarded  uint64 `json:"forwarded"`
	Dropped    uint64 `json:"dropped"`
	Shaped     uint64 `json:"shaped"`
	Replies    uint64 `json:"replies"`
	Rewrites   uint64 `json:"rewrites"`
	Fragments  uint64 `json:"fragments"`
	Redirects  uint64 `json:"redirects"`
	SendErrors uint64 `json:"sendErrors"`
}

type RelayEvent struct {
	Time      string `json:"time"`
	Device    string `json:"device"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Reason    string `json:"reason,omitempty"`
	Protocol  string `json:"protocol"`
	SrcPort   uint16 `json:"srcPort,omitempty"`
	DstPort   uint16 `json:"dstPort,omitempty"`
}

type relayDeviceCounters struct {
	received, ipv6, forwarded, dropped, shaped uint64
	replies, rewrites, fragments, redirects    uint64
	sendErrors                                 uint64
}

type relayFlow struct {
	device           netip.Addr
	dir              Direction
	protocol         string
	srcPort, dstPort uint16
}

type relaySendMeta struct {
	action string
	reason string
	add    func()
	update func(*relayDeviceCounters)
}

func NewRelay(h Handle, iface Interface, gwIP net.IP, gwMAC []byte, table *Table, dec Decider) *Relay {
	return &Relay{handle: h, iface: iface, gwIP: gwIP, gwMAC: gwMAC, table: table, dec: dec, byDevice: make(map[netip.Addr]*relayDeviceCounters)}
}

// SetInspector attaches a content filter consulted before forwarding. Optional; nil disables it.
func (r *Relay) SetInspector(i FlowInspector) { r.inspect = i }

func (r *Relay) SetIPv6LearnedHook(fn func()) { r.onV6Learned = fn }

func (r *Relay) Stats() RelayStats {
	if r == nil {
		return RelayStats{}
	}
	devices, recent := r.deviceStats()
	return RelayStats{
		Received:   r.rx.Load(),
		IPv6:       r.rx6.Load(),
		Forwarded:  r.fwd.Load(),
		Dropped:    r.drop.Load(),
		Shaped:     r.delay.Load(),
		Replies:    r.replies.Load(),
		Rewrites:   r.rewrites.Load(),
		Fragments:  r.fragments.Load(),
		Redirects:  r.redirects.Load(),
		SendErrors: r.sendErrs.Load(),
		Devices:    devices,
		Recent:     recent,
	}
}

// Run forwards intercepted IP traffic until ctx is canceled. The BPF filter keeps only IP
// frames addressed to us, so the relay does not burn cycles on traffic it would ignore anyway.
func (r *Relay) Run(ctx context.Context) error {
	_ = r.handle.SetBPF("ether dst " + r.iface.MAC.String() + " and (ip or ip6)")
	go r.logStats(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		pkt, err := r.handle.Recv()
		if err != nil {
			continue
		}
		r.handlePacket(ctx, pkt)
	}
}

// logStats prints relay counters whenever they change, so the operator can confirm the relay is
// actually carrying the target's traffic (rx > 0) and forwarding it.
func (r *Relay) logStats(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var prev uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rx := r.rx.Load()
			if rx == prev {
				continue
			}
			prev = rx
			log.Printf("relay: rx=%d (ipv6=%d) fwd=%d drop=%d shaped=%d replies=%d rewrites=%d sendErr=%d",
				rx, r.rx6.Load(), r.fwd.Load(), r.drop.Load(), r.delay.Load(), r.replies.Load(), r.rewrites.Load(), r.sendErrs.Load())
		}
	}
}

func (r *Relay) send(frame []byte) {
	if err := r.handle.Send(frame); err != nil {
		if r.sendErrs.Add(1) == 1 {
			log.Printf("relay: packet injection failed (will suppress further): %v", err)
		}
		return
	}
	r.fwd.Add(1)
}

func (r *Relay) sendObserved(flow relayFlow, meta relaySendMeta, frame []byte) {
	if err := r.handle.Send(frame); err != nil {
		if r.sendErrs.Add(1) == 1 {
			log.Printf("relay: packet injection failed (will suppress further): %v", err)
		}
		r.recordDeviceEvent(flow, "error", "send", func(c *relayDeviceCounters) { c.sendErrors++ })
		return
	}
	r.fwd.Add(1)
	if meta.add != nil {
		meta.add()
	}
	r.recordDeviceEvent(flow, meta.action, meta.reason, func(c *relayDeviceCounters) {
		c.forwarded++
		if meta.update != nil {
			meta.update(c)
		}
	})
}

func (r *Relay) handlePacket(ctx context.Context, pkt gopacket.Packet) {
	raw := pkt.Data()
	if len(raw) < 14 {
		return
	}

	var (
		dir     Direction
		device  netip.Addr
		nextHop []byte
		ok      bool
		v6      bool
	)
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		dir, device, nextHop, ok = r.route(l.(*layers.IPv4), raw)
	} else if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		v6 = true
		dir, device, nextHop, ok = r.route6(l.(*layers.IPv6), raw)
	}
	if !ok {
		return
	}

	flow := relayFlow{device: device, dir: dir, protocol: "ip"}
	r.recordReceive(device, v6)
	fragmented := fragmentedIP(pkt)

	// Never relay an ICMP redirect to a device: a real gateway sends these to steer the device
	// back to itself, which would undo the poisoning. Dropping them keeps the device on our path.
	if isICMPRedirect(pkt) {
		flow.protocol = "icmp"
		r.recordDrop(flow, "icmp_redirect")
		return
	}

	framed := false
	sendMeta := relaySendMeta{}
	udp, sport, dport, payload, hasTransport := transport(pkt)
	if hasTransport {
		flow.protocol = transportProtocol(udp)
		flow.srcPort, flow.dstPort = sport, dport
	}
	if r.inspect != nil {
		if hasTransport {
			action := r.inspectFlow(FlowContext{
				Device:    device,
				Direction: dir,
				UDP:       udp,
				SrcIP:     packetSrcIP(pkt),
				DstIP:     packetDstIP(pkt),
				SrcPort:   sport,
				DstPort:   dport,
				Payload:   payload,
			})
			switch action.Kind {
			case FlowReply:
				if !udp || dir != Upload || dport != portDNS || dnsRewriteUnsafe(pkt) {
					r.recordDrop(flow, "unsafe_dns_reply")
					r.rejectUDPToDevice(flow, pkt, dir, nextHop)
					return
				}
				frame, ok := udpReplyFrame(pkt, r.iface.MAC, action.Payload)
				if !ok {
					r.recordDrop(flow, "dns_reply_error")
					return
				}
				r.sendObserved(flow, relaySendMeta{
					action: "reply",
					reason: "dns_reply",
					add:    func() { r.replies.Add(1) },
					update: func(c *relayDeviceCounters) { c.replies++ },
				}, frame)
				return
			case FlowDrop:
				r.recordDrop(flow, "filter")
				r.rejectTCP(flow, pkt, dir, nextHop)
				r.rejectUDP(flow, pkt, dir, nextHop)
				return
			case FlowReplace:
				if !udp || dir != Download || sport != portDNS || dnsRewriteUnsafe(pkt) {
					r.recordDrop(flow, "unsafe_dns_rewrite")
					r.rejectUDP(flow, pkt, dir, nextHop)
					return
				}
				frame, ok := rewriteUDPPayload(pkt, nextHop, r.iface.MAC, action.Payload)
				if !ok {
					r.recordDrop(flow, "dns_rewrite_error")
					return
				}
				raw = frame
				framed = true
				sendMeta = relaySendMeta{
					action: "rewrite",
					reason: "dns_rewrite",
					add:    func() { r.rewrites.Add(1) },
					update: func(c *relayDeviceCounters) { c.rewrites++ },
				}
			}
		}
	}

	if r.dec != nil {
		drop, delay := r.dec.Decide(device, dir, len(raw))
		if drop {
			r.recordDrop(flow, "enforcement")
			r.rejectTCP(flow, pkt, dir, nextHop)
			r.rejectUDP(flow, pkt, dir, nextHop)
			return
		}
		if fragmented {
			r.recordDrop(flow, "fragment")
			return
		}
		if delay > 0 {
			frame := raw
			if !framed {
				frame = rewriteNextHop(raw, nextHop, r.iface.MAC)
			}
			r.recordShape(flow)
			if sendMeta.action == "" {
				sendMeta.action = "forward"
				sendMeta.reason = "delayed"
			}
			r.scheduleObservedSend(ctx, delay, flow, sendMeta, frame)
			return
		}
	}
	if fragmented {
		r.recordDrop(flow, "fragment")
		return
	}
	frame := raw
	if !framed {
		frame = rewriteNextHop(raw, nextHop, r.iface.MAC)
	}
	r.sendObserved(flow, sendMeta, frame)
}

func (r *Relay) inspectFlow(ctx FlowContext) FlowAction {
	if inspector, ok := r.inspect.(FlowContextInspector); ok {
		return inspector.InspectFlowContext(ctx)
	}
	return r.inspect.InspectFlow(ctx.Device, ctx.Direction, ctx.UDP, ctx.SrcPort, ctx.DstPort, ctx.Payload)
}

func (r *Relay) scheduleSend(ctx context.Context, delay time.Duration, frame []byte) {
	timer := time.NewTimer(delay)
	go func() {
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.send(frame)
		}
	}()
}

func (r *Relay) scheduleObservedSend(ctx context.Context, delay time.Duration, flow relayFlow, meta relaySendMeta, frame []byte) {
	timer := time.NewTimer(delay)
	go func() {
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			r.sendObserved(flow, meta, frame)
		}
	}()
}

func (r *Relay) recordReceive(device netip.Addr, v6 bool) {
	r.rx.Add(1)
	if v6 {
		r.rx6.Add(1)
	}
	r.mu.Lock()
	c := r.countersLocked(device)
	c.received++
	if v6 {
		c.ipv6++
	}
	r.mu.Unlock()
}

func (r *Relay) recordDrop(flow relayFlow, reason string) {
	r.drop.Add(1)
	switch reason {
	case "fragment":
		r.fragments.Add(1)
	case "icmp_redirect":
		r.redirects.Add(1)
	}
	r.recordDeviceEvent(flow, "drop", reason, func(c *relayDeviceCounters) {
		c.dropped++
		switch reason {
		case "fragment":
			c.fragments++
		case "icmp_redirect":
			c.redirects++
		}
	})
}

func (r *Relay) recordShape(flow relayFlow) {
	r.delay.Add(1)
	r.recordDeviceEvent(flow, "shape", "rate_limit", func(c *relayDeviceCounters) { c.shaped++ })
}

func (r *Relay) rejectTCP(flow relayFlow, pkt gopacket.Packet, dir Direction, nextHop net.HardwareAddr) {
	r.rejectTCPToDevice(flow, pkt, dir, nextHop)
	r.rejectTCPToRemote(flow, pkt, dir)
}

func (r *Relay) rejectTCPToDevice(flow relayFlow, pkt gopacket.Packet, dir Direction, nextHop net.HardwareAddr) {
	frame, ok := tcpResetToDeviceFrame(pkt, dir, r.iface.MAC, nextHop)
	if !ok {
		return
	}
	r.sendControlFrame(flow, frame)
}

func (r *Relay) rejectTCPToRemote(flow relayFlow, pkt gopacket.Packet, dir Direction) {
	frame, ok := tcpResetToRemoteFrame(pkt, dir, r.iface.MAC, r.gwMAC)
	if !ok {
		return
	}
	r.sendControlFrame(flow, frame)
}

func (r *Relay) rejectUDPToDevice(flow relayFlow, pkt gopacket.Packet, dir Direction, nextHop net.HardwareAddr) {
	if flow.protocol != "udp" {
		return
	}
	frame, ok := icmpUnreachableToDeviceFrame(pkt, dir, r.iface.MAC, nextHop)
	if !ok {
		return
	}
	r.sendControlFrame(flow, frame)
}

func (r *Relay) rejectUDP(flow relayFlow, pkt gopacket.Packet, dir Direction, nextHop net.HardwareAddr) {
	r.rejectUDPToDevice(flow, pkt, dir, nextHop)
	r.rejectUDPToRemote(flow, pkt, dir)
}

func (r *Relay) rejectUDPToRemote(flow relayFlow, pkt gopacket.Packet, dir Direction) {
	if flow.protocol != "udp" || dir != Download {
		return
	}
	frame, ok := icmpUnreachableToRemoteFrame(pkt, r.iface.MAC, r.gwMAC)
	if !ok {
		return
	}
	r.sendControlFrame(flow, frame)
}

func (r *Relay) sendControlFrame(flow relayFlow, frame []byte) {
	if err := r.handle.Send(frame); err != nil {
		if r.sendErrs.Add(1) == 1 {
			log.Printf("relay: packet injection failed (will suppress further): %v", err)
		}
		r.recordDeviceEvent(flow, "error", "send", func(c *relayDeviceCounters) { c.sendErrors++ })
	}
}

func (r *Relay) recordDeviceEvent(flow relayFlow, action, reason string, update func(*relayDeviceCounters)) {
	if !flow.device.IsValid() {
		return
	}
	if flow.protocol == "" {
		flow.protocol = "ip"
	}
	r.mu.Lock()
	c := r.countersLocked(flow.device)
	if update != nil {
		update(c)
	}
	if action == "" {
		r.mu.Unlock()
		return
	}
	r.appendEventLocked(RelayEvent{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Device:    flow.device.String(),
		Direction: directionLabel(flow.dir),
		Action:    action,
		Reason:    reason,
		Protocol:  flow.protocol,
		SrcPort:   flow.srcPort,
		DstPort:   flow.dstPort,
	})
	r.mu.Unlock()
}

func (r *Relay) countersLocked(device netip.Addr) *relayDeviceCounters {
	if r.byDevice == nil {
		r.byDevice = make(map[netip.Addr]*relayDeviceCounters)
	}
	c := r.byDevice[device]
	if c == nil {
		c = &relayDeviceCounters{}
		r.byDevice[device] = c
	}
	return c
}

func (r *Relay) appendEventLocked(event RelayEvent) {
	if len(r.recent) < maxRelayEvents {
		r.recent = append(r.recent, event)
		return
	}
	copy(r.recent, r.recent[1:])
	r.recent[len(r.recent)-1] = event
}

func (r *Relay) deviceStats() ([]RelayDeviceStats, []RelayEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	devices := make([]RelayDeviceStats, 0, len(r.byDevice))
	for device, c := range r.byDevice {
		devices = append(devices, RelayDeviceStats{
			Device:     device.String(),
			Received:   c.received,
			IPv6:       c.ipv6,
			Forwarded:  c.forwarded,
			Dropped:    c.dropped,
			Shaped:     c.shaped,
			Replies:    c.replies,
			Rewrites:   c.rewrites,
			Fragments:  c.fragments,
			Redirects:  c.redirects,
			SendErrors: c.sendErrors,
		})
	}
	sort.Slice(devices, func(i, j int) bool {
		a, _ := netip.ParseAddr(devices[i].Device)
		b, _ := netip.ParseAddr(devices[j].Device)
		return a.Compare(b) < 0
	})
	recent := append([]RelayEvent(nil), r.recent...)
	return devices, recent
}

func directionLabel(dir Direction) string {
	if dir == Upload {
		return "upload"
	}
	return "download"
}

func transportProtocol(udp bool) string {
	if udp {
		return "udp"
	}
	return "tcp"
}

// route classifies an intercepted packet and returns the device it belongs to and the MAC of
// the real next hop to send it to. Traffic to an off-subnet address is upload (forward to the
// gateway); traffic to an on-subnet host is download (forward to that host's real MAC).
func (r *Relay) route(ip *layers.IPv4, raw []byte) (Direction, netip.Addr, []byte, bool) {
	_, srcOK := netip.AddrFromSlice(ip.SrcIP.To4())
	dst, dstOK := netip.AddrFromSlice(ip.DstIP.To4())
	if !srcOK || !dstOK {
		return 0, netip.Addr{}, nil, false
	}

	if !r.iface.Subnet.Contains(ip.DstIP) {
		device, ok := r.ipv4SourceIdentity(raw, ip.SrcIP)
		return Upload, device, r.gwMAC, ok
	}
	if r.gwIP != nil && ip.DstIP.Equal(r.gwIP) {
		device, ok := r.ipv4SourceIdentity(raw, ip.SrcIP)
		return Upload, device, r.gwMAC, ok
	}
	if !r.sourceIsGateway(raw) {
		return 0, netip.Addr{}, nil, false
	}
	if d, ok := r.table.GetByIP(ip.DstIP); ok {
		return Download, dst, d.MAC, true
	}
	return 0, netip.Addr{}, nil, false
}

func (r *Relay) sourceIsGateway(raw []byte) bool {
	return len(raw) >= 12 && bytes.Equal(raw[6:12], r.gwMAC)
}

func (r *Relay) ipv4SourceIdentity(raw []byte, srcIP net.IP) (netip.Addr, bool) {
	if r.table == nil || len(raw) < 12 {
		return netip.Addr{}, false
	}
	if dev, ok := r.table.Get(net.HardwareAddr(raw[6:12])); ok {
		if !dev.IP.Equal(srcIP) {
			return netip.Addr{}, false
		}
		if key, ok := netip.AddrFromSlice(dev.IP.To4()); ok {
			return key, true
		}
	}
	return netip.Addr{}, false
}

// route6 classifies a captured IPv6 frame. Policy is keyed on the device's IPv4 address (found by
// MAC) so one rule covers a device's IPv4 and IPv6 traffic.
//   - Gateway-sourced frame to a device we know an IPv6 for => Download (forward to the device).
//   - Device-sourced unicast frame from a known MAC => Upload (forward to the gateway). This
//     includes DNS to the router's link-local address, which is common on IPv6 LANs.
func (r *Relay) route6(ip6 *layers.IPv6, raw []byte) (Direction, netip.Addr, []byte, bool) {
	if r.table == nil {
		return 0, netip.Addr{}, nil, false
	}
	srcMAC := net.HardwareAddr(raw[6:12])

	if bytes.Equal(srcMAC, r.gwMAC) {
		if dev, ok := r.table.DeviceByV6(ip6.DstIP); ok {
			if key, ok := netip.AddrFromSlice(dev.IP.To4()); ok {
				return Download, key, dev.MAC, true
			}
		}
		return 0, netip.Addr{}, nil, false
	}

	if !forwardableIPv6Destination(ip6.DstIP) {
		return 0, netip.Addr{}, nil, false
	}
	dev, ok := r.table.Get(srcMAC)
	if !ok {
		return 0, netip.Addr{}, nil, false
	}
	if r.table.RecordV6(srcMAC, ip6.SrcIP) {
		r.notifyIPv6Learned()
	}
	key, ok := netip.AddrFromSlice(dev.IP.To4())
	if !ok {
		return 0, netip.Addr{}, nil, false
	}
	return Upload, key, r.gwMAC, true
}

func (r *Relay) notifyIPv6Learned() {
	if r.onV6Learned != nil {
		r.onV6Learned()
	}
}

func forwardableIPv6Destination(ip net.IP) bool {
	v6 := ip.To16()
	return v6 != nil && v6.To4() == nil && usableIPv6Unicast(v6)
}

// transport returns the transport protocol, destination port, and application payload of a
// packet, or ok=false if it carries neither TCP nor UDP.
func transport(pkt gopacket.Packet) (udp bool, srcPort, dstPort uint16, payload []byte, ok bool) {
	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		tcp := l.(*layers.TCP)
		return false, uint16(tcp.SrcPort), uint16(tcp.DstPort), tcp.LayerPayload(), true
	}
	if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		u := l.(*layers.UDP)
		return true, uint16(u.SrcPort), uint16(u.DstPort), u.LayerPayload(), true
	}
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		return transportFromIPv4(l.(*layers.IPv4))
	}
	if l := pkt.Layer(layers.LayerTypeIPv6Fragment); l != nil {
		return transportFromIPv6Fragment(l.(*layers.IPv6Fragment))
	}
	return false, 0, 0, nil, false
}

func transportFromIPv4(ip *layers.IPv4) (udp bool, srcPort, dstPort uint16, payload []byte, ok bool) {
	if ip == nil || ip.FragOffset != 0 {
		return false, 0, 0, nil, false
	}
	return transportFromPayload(ip.Protocol, ip.Payload)
}

func transportFromIPv6Fragment(fragment *layers.IPv6Fragment) (udp bool, srcPort, dstPort uint16, payload []byte, ok bool) {
	if fragment == nil || fragment.FragmentOffset != 0 {
		return false, 0, 0, nil, false
	}
	return transportFromPayload(fragment.NextHeader, fragment.LayerPayload())
}

func transportFromPayload(proto layers.IPProtocol, payload []byte) (udp bool, srcPort, dstPort uint16, appPayload []byte, ok bool) {
	switch proto {
	case layers.IPProtocolUDP:
		if len(payload) < 8 {
			return false, 0, 0, nil, false
		}
		return true, binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint16(payload[2:4]), payload[8:], true
	case layers.IPProtocolTCP:
		if len(payload) < 20 {
			return false, 0, 0, nil, false
		}
		headerLen := int(payload[12]>>4) * 4
		if headerLen < 20 || len(payload) < headerLen {
			return false, 0, 0, nil, false
		}
		return false, binary.BigEndian.Uint16(payload[:2]), binary.BigEndian.Uint16(payload[2:4]), payload[headerLen:], true
	default:
		return false, 0, 0, nil, false
	}
}

func packetSrcIP(pkt gopacket.Packet) netip.Addr {
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		addr, _ := netip.AddrFromSlice(l.(*layers.IPv4).SrcIP.To4())
		return addr
	}
	if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		addr, _ := netip.AddrFromSlice(l.(*layers.IPv6).SrcIP.To16())
		return addr
	}
	return netip.Addr{}
}

func packetDstIP(pkt gopacket.Packet) netip.Addr {
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		addr, _ := netip.AddrFromSlice(l.(*layers.IPv4).DstIP.To4())
		return addr
	}
	if l := pkt.Layer(layers.LayerTypeIPv6); l != nil {
		addr, _ := netip.AddrFromSlice(l.(*layers.IPv6).DstIP.To16())
		return addr
	}
	return netip.Addr{}
}

func isICMPRedirect(pkt gopacket.Packet) bool {
	l := pkt.Layer(layers.LayerTypeICMPv4)
	if l == nil {
		return false
	}
	return l.(*layers.ICMPv4).TypeCode.Type() == layers.ICMPv4TypeRedirect
}

func dnsRewriteUnsafe(pkt gopacket.Packet) bool {
	return fragmentedIP(pkt)
}

func fragmentedIP(pkt gopacket.Packet) bool {
	if l := pkt.Layer(layers.LayerTypeIPv4); l != nil {
		ip := l.(*layers.IPv4)
		return ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0
	}
	return pkt.Layer(layers.LayerTypeIPv6Fragment) != nil
}

// rewriteNextHop returns a copy of frame with the Ethernet destination set to nextHop and the
// source set to self, leaving the IP payload untouched.
func rewriteNextHop(frame, nextHop, self []byte) []byte {
	out := make([]byte, len(frame))
	copy(out, frame)
	copy(out[0:6], nextHop)
	copy(out[6:12], self)
	return out
}

func rewriteUDPPayload(pkt gopacket.Packet, nextHop, self net.HardwareAddr, payload []byte) ([]byte, bool) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if ethLayer == nil || udpLayer == nil {
		return nil, false
	}
	eth := *ethLayer.(*layers.Ethernet)
	eth.SrcMAC = append(net.HardwareAddr(nil), self...)
	eth.DstMAC = append(net.HardwareAddr(nil), nextHop...)

	udp := *udpLayer.(*layers.UDP)
	return serializeUDP(pkt, &eth, &udp, payload, false)
}

func udpReplyFrame(pkt gopacket.Packet, self net.HardwareAddr, payload []byte) ([]byte, bool) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if ethLayer == nil || udpLayer == nil {
		return nil, false
	}
	origEth := ethLayer.(*layers.Ethernet)
	eth := *origEth
	eth.SrcMAC = append(net.HardwareAddr(nil), self...)
	eth.DstMAC = append(net.HardwareAddr(nil), origEth.SrcMAC...)

	origUDP := udpLayer.(*layers.UDP)
	udp := *origUDP
	udp.SrcPort, udp.DstPort = origUDP.DstPort, origUDP.SrcPort
	return serializeUDP(pkt, &eth, &udp, payload, true)
}

func tcpResetToDeviceFrame(pkt gopacket.Packet, dir Direction, self, nextHop net.HardwareAddr) ([]byte, bool) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if ethLayer == nil || tcpLayer == nil {
		return nil, false
	}
	origEth := ethLayer.(*layers.Ethernet)
	origTCP := tcpLayer.(*layers.TCP)

	eth := *origEth
	eth.SrcMAC = append(net.HardwareAddr(nil), self...)
	if dir == Upload {
		eth.DstMAC = append(net.HardwareAddr(nil), origEth.SrcMAC...)
	} else {
		if len(nextHop) == 0 {
			return nil, false
		}
		eth.DstMAC = append(net.HardwareAddr(nil), nextHop...)
	}

	tcp := &layers.TCP{
		RST:     true,
		ACK:     true,
		Seq:     origTCP.Ack,
		Ack:     origTCP.Seq + tcpSegmentLength(origTCP),
		Window:  0,
		SrcPort: origTCP.DstPort,
		DstPort: origTCP.SrcPort,
	}
	swapIP := true
	if dir == Download {
		tcp.Seq = origTCP.Seq
		tcp.Ack = origTCP.Ack
		tcp.SrcPort = origTCP.SrcPort
		tcp.DstPort = origTCP.DstPort
		swapIP = false
	}
	return serializeTCP(pkt, &eth, tcp, nil, swapIP)
}

func tcpResetToRemoteFrame(pkt gopacket.Packet, dir Direction, self, gwMAC net.HardwareAddr) ([]byte, bool) {
	if len(gwMAC) == 0 {
		return nil, false
	}
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if ethLayer == nil || tcpLayer == nil {
		return nil, false
	}
	origEth := ethLayer.(*layers.Ethernet)
	origTCP := tcpLayer.(*layers.TCP)
	if !origTCP.ACK {
		return nil, false
	}

	eth := *origEth
	eth.SrcMAC = append(net.HardwareAddr(nil), self...)
	eth.DstMAC = append(net.HardwareAddr(nil), gwMAC...)

	tcp := &layers.TCP{
		RST:     true,
		ACK:     true,
		Seq:     origTCP.Seq,
		Ack:     origTCP.Ack,
		Window:  0,
		SrcPort: origTCP.SrcPort,
		DstPort: origTCP.DstPort,
	}
	swapIP := false
	if dir == Download {
		tcp.Seq = origTCP.Ack
		tcp.Ack = origTCP.Seq + tcpSegmentLength(origTCP)
		tcp.SrcPort = origTCP.DstPort
		tcp.DstPort = origTCP.SrcPort
		swapIP = true
	}
	return serializeTCP(pkt, &eth, tcp, nil, swapIP)
}

func tcpSegmentLength(tcp *layers.TCP) uint32 {
	payloadLen := len(tcp.LayerPayload())
	if uint64(payloadLen) > uint64(^uint32(0)-2) {
		return ^uint32(0)
	}
	length := uint32(payloadLen) // #nosec G115 -- payloadLen is bounded above before conversion.
	if tcp.SYN {
		length++
	}
	if tcp.FIN {
		length++
	}
	return length
}

func icmpUnreachableToDeviceFrame(pkt gopacket.Packet, dir Direction, self, nextHop net.HardwareAddr) ([]byte, bool) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, false
	}
	origEth := ethLayer.(*layers.Ethernet)

	eth := *origEth
	eth.SrcMAC = append(net.HardwareAddr(nil), self...)
	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		return icmpv4UnreachableToDeviceFrame(pkt, &eth, ip4Layer.(*layers.IPv4), dir, nextHop)
	}
	if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		return icmpv6UnreachableToDeviceFrame(pkt, &eth, ip6Layer.(*layers.IPv6), dir, nextHop)
	}
	return nil, false
}

func icmpUnreachableToRemoteFrame(pkt gopacket.Packet, self, gwMAC net.HardwareAddr) ([]byte, bool) {
	if len(gwMAC) == 0 {
		return nil, false
	}
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, false
	}
	eth := *ethLayer.(*layers.Ethernet)
	eth.SrcMAC = append(net.HardwareAddr(nil), self...)
	eth.DstMAC = append(net.HardwareAddr(nil), gwMAC...)
	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		return icmpv4UnreachableToRemoteFrame(&eth, ip4Layer.(*layers.IPv4))
	}
	if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		return icmpv6UnreachableToRemoteFrame(&eth, ip6Layer.(*layers.IPv6))
	}
	return nil, false
}

func icmpv4UnreachableToDeviceFrame(pkt gopacket.Packet, eth *layers.Ethernet, origIP *layers.IPv4, dir Direction, nextHop net.HardwareAddr) ([]byte, bool) {
	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolICMPv4}
	if dir == Upload {
		eth.DstMAC = append(net.HardwareAddr(nil), ethLayerSrc(pkt)...)
		ip.SrcIP = append(net.IP(nil), origIP.DstIP...)
		ip.DstIP = append(net.IP(nil), origIP.SrcIP...)
	} else {
		if len(nextHop) == 0 {
			return nil, false
		}
		eth.DstMAC = append(net.HardwareAddr(nil), nextHop...)
		ip.SrcIP = append(net.IP(nil), origIP.SrcIP...)
		ip.DstIP = append(net.IP(nil), origIP.DstIP...)
	}

	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, icmp, gopacket.Payload(quotedIPv4PacketPrefix(origIP))); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

func icmpv4UnreachableToRemoteFrame(eth *layers.Ethernet, origIP *layers.IPv4) ([]byte, bool) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    append(net.IP(nil), origIP.DstIP...),
		DstIP:    append(net.IP(nil), origIP.SrcIP...),
	}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort)}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, icmp, gopacket.Payload(quotedIPv4PacketPrefix(origIP))); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

func icmpv6UnreachableToDeviceFrame(pkt gopacket.Packet, eth *layers.Ethernet, origIP *layers.IPv6, dir Direction, nextHop net.HardwareAddr) ([]byte, bool) {
	ip := &layers.IPv6{Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolICMPv6}
	if dir == Upload {
		eth.DstMAC = append(net.HardwareAddr(nil), ethLayerSrc(pkt)...)
		ip.SrcIP = append(net.IP(nil), origIP.DstIP...)
		ip.DstIP = append(net.IP(nil), origIP.SrcIP...)
	} else {
		if len(nextHop) == 0 {
			return nil, false
		}
		eth.DstMAC = append(net.HardwareAddr(nil), nextHop...)
		ip.SrcIP = append(net.IP(nil), origIP.SrcIP...)
		ip.DstIP = append(net.IP(nil), origIP.DstIP...)
	}

	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, false
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, icmp, gopacket.Payload(quotedIPv6PacketPrefix(origIP))); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

func icmpv6UnreachableToRemoteFrame(eth *layers.Ethernet, origIP *layers.IPv6) ([]byte, bool) {
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolICMPv6,
		SrcIP:      append(net.IP(nil), origIP.DstIP...),
		DstIP:      append(net.IP(nil), origIP.SrcIP...),
	}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable)}
	if err := icmp.SetNetworkLayerForChecksum(ip); err != nil {
		return nil, false
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, icmp, gopacket.Payload(quotedIPv6PacketPrefix(origIP))); err != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

func ethLayerSrc(pkt gopacket.Packet) net.HardwareAddr {
	if ethLayer := pkt.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		return ethLayer.(*layers.Ethernet).SrcMAC
	}
	return nil
}

func quotedIPv4PacketPrefix(ip *layers.IPv4) []byte {
	out := append([]byte(nil), ip.Contents...)
	n := len(ip.Payload)
	if n > 8 {
		n = 8
	}
	return append(out, ip.Payload[:n]...)
}

func quotedIPv6PacketPrefix(ip *layers.IPv6) []byte {
	out := append([]byte(nil), ip.Contents...)
	n := len(ip.Payload)
	if n > 8 {
		n = 8
	}
	return append(out, ip.Payload[:n]...)
}

func serializeTCP(pkt gopacket.Packet, eth *layers.Ethernet, tcp *layers.TCP, payload []byte, swapIP bool) ([]byte, bool) {
	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip := *ip4Layer.(*layers.IPv4)
		if swapIP {
			ip.SrcIP, ip.DstIP = append(net.IP(nil), ip.DstIP...), append(net.IP(nil), ip.SrcIP...)
			ip.TTL = 64
		}
		ip.Protocol = layers.IPProtocolTCP
		if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
			return nil, false
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, serializeOptions, eth, &ip, tcp, gopacket.Payload(payload)); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	}

	if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip := *ip6Layer.(*layers.IPv6)
		if swapIP {
			ip.SrcIP, ip.DstIP = append(net.IP(nil), ip.DstIP...), append(net.IP(nil), ip.SrcIP...)
			ip.HopLimit = 64
		}
		ip.NextHeader = layers.IPProtocolTCP
		if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
			return nil, false
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, serializeOptions, eth, &ip, tcp, gopacket.Payload(payload)); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	}
	return nil, false
}

func serializeUDP(pkt gopacket.Packet, eth *layers.Ethernet, udp *layers.UDP, payload []byte, swapIP bool) ([]byte, bool) {
	if ip4Layer := pkt.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
		ip := *ip4Layer.(*layers.IPv4)
		if swapIP {
			ip.SrcIP, ip.DstIP = append(net.IP(nil), ip.DstIP...), append(net.IP(nil), ip.SrcIP...)
			ip.TTL = 64
		}
		ip.Protocol = layers.IPProtocolUDP
		if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
			return nil, false
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, serializeOptions, eth, &ip, udp, gopacket.Payload(payload)); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	}

	if ip6Layer := pkt.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip := *ip6Layer.(*layers.IPv6)
		if swapIP {
			ip.SrcIP, ip.DstIP = append(net.IP(nil), ip.DstIP...), append(net.IP(nil), ip.SrcIP...)
			ip.HopLimit = 64
		}
		ip.NextHeader = layers.IPProtocolUDP
		if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
			return nil, false
		}
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, serializeOptions, eth, &ip, udp, gopacket.Payload(payload)); err != nil {
			return nil, false
		}
		return buf.Bytes(), true
	}
	return nil, false
}
