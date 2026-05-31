package engine

import (
	"context"
	"log"
	"net/netip"
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

// Decider decides what the relay does with one intercepted packet. A nil Decider forwards
// everything unchanged. delay > 0 means hold the packet that long before forwarding (shaping);
// drop means discard it (block).
type Decider interface {
	Decide(device netip.Addr, dir Direction, length int) (drop bool, delay time.Duration)
}

// FlowInspector inspects a transport flow for content policy (blocked domains, QUIC, VPN ports).
// payload is the application data (a DNS message on UDP/53, a TLS record on TCP/443). Returning
// true drops the packet.
type FlowInspector interface {
	InspectFlow(device netip.Addr, udp bool, dstPort uint16, payload []byte) (drop bool)
}

// Relay is the userspace forwarding path. Once targets are poisoned, their frames arrive at our
// MAC; the relay applies policy and re-injects them toward the real next hop. Forwarding in user
// space (rather than the kernel) is what lets the Decider shape and block traffic uniformly
// across platforms.
type Relay struct {
	handle  Handle
	iface   Interface
	gwMAC   []byte
	table   *Table
	dec     Decider
	inspect FlowInspector

	// Diagnostic counters (atomic): rx = intercepted IPv4 frames routed, fwd = forwarded,
	// drop = blocked, delay = shaped. They reveal whether the relay is actually on the path.
	rx, fwd, drop, delay atomic.Uint64
	sendErrs             atomic.Uint64
}

func NewRelay(h Handle, iface Interface, gwMAC []byte, table *Table, dec Decider) *Relay {
	return &Relay{handle: h, iface: iface, gwMAC: gwMAC, table: table, dec: dec}
}

// SetInspector attaches a content filter consulted before forwarding. Optional; nil disables it.
func (r *Relay) SetInspector(i FlowInspector) { r.inspect = i }

// Run forwards intercepted IPv4 traffic until ctx is cancelled. The BPF filter keeps only IP
// frames addressed to us, so the relay does not burn cycles on traffic it would ignore anyway.
func (r *Relay) Run(ctx context.Context) error {
	_ = r.handle.SetBPF("ether dst " + r.iface.MAC.String() + " and ip")
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
		r.handlePacket(pkt)
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
			log.Printf("relay: rx=%d fwd=%d drop=%d shaped=%d sendErr=%d",
				rx, r.fwd.Load(), r.drop.Load(), r.delay.Load(), r.sendErrs.Load())
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

func (r *Relay) handlePacket(pkt gopacket.Packet) {
	netLayer := pkt.Layer(layers.LayerTypeIPv4)
	if netLayer == nil {
		return
	}
	ip := netLayer.(*layers.IPv4)

	dir, device, nextHop, ok := r.route(ip)
	if !ok {
		return
	}

	raw := pkt.Data()
	if len(raw) < 14 {
		return
	}
	r.rx.Add(1)

	// Never relay an ICMP redirect to a device: a real gateway sends these to steer the device
	// back to itself, which would undo the poisoning. Dropping them keeps the device on our path.
	if isICMPRedirect(pkt) {
		r.drop.Add(1)
		return
	}

	if r.inspect != nil {
		if udp, dport, payload, ok := transport(pkt); ok {
			if r.inspect.InspectFlow(device, udp, dport, payload) {
				r.drop.Add(1)
				return
			}
		}
	}

	if r.dec != nil {
		drop, delay := r.dec.Decide(device, dir, len(raw))
		if drop {
			r.drop.Add(1)
			return
		}
		if delay > 0 {
			frame := rewriteNextHop(raw, nextHop, r.iface.MAC)
			r.delay.Add(1)
			time.AfterFunc(delay, func() { r.send(frame) })
			return
		}
	}
	r.send(rewriteNextHop(raw, nextHop, r.iface.MAC))
}

// route classifies an intercepted packet and returns the device it belongs to and the MAC of
// the real next hop to send it to. Traffic to an off-subnet address is upload (forward to the
// gateway); traffic to an on-subnet host is download (forward to that host's real MAC).
func (r *Relay) route(ip *layers.IPv4) (Direction, netip.Addr, []byte, bool) {
	src, srcOK := netip.AddrFromSlice(ip.SrcIP.To4())
	dst, dstOK := netip.AddrFromSlice(ip.DstIP.To4())
	if !srcOK || !dstOK {
		return 0, netip.Addr{}, nil, false
	}

	if !r.iface.Subnet.Contains(ip.DstIP) {
		return Upload, src, r.gwMAC, true
	}
	if d, ok := r.table.GetByIP(ip.DstIP); ok {
		return Download, dst, d.MAC, true
	}
	return 0, netip.Addr{}, nil, false
}

// transport returns the transport protocol, destination port, and application payload of a
// packet, or ok=false if it carries neither TCP nor UDP.
func transport(pkt gopacket.Packet) (udp bool, dstPort uint16, payload []byte, ok bool) {
	if l := pkt.Layer(layers.LayerTypeTCP); l != nil {
		tcp := l.(*layers.TCP)
		return false, uint16(tcp.DstPort), tcp.LayerPayload(), true
	}
	if l := pkt.Layer(layers.LayerTypeUDP); l != nil {
		u := l.(*layers.UDP)
		return true, uint16(u.DstPort), u.LayerPayload(), true
	}
	return false, 0, nil, false
}

func isICMPRedirect(pkt gopacket.Packet) bool {
	l := pkt.Layer(layers.LayerTypeICMPv4)
	if l == nil {
		return false
	}
	return l.(*layers.ICMPv4).TypeCode.Type() == layers.ICMPv4TypeRedirect
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
