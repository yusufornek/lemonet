package engine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Scanner discovers hosts on the local subnet by active ARP sweep. It reuses an open Handle so
// the caller controls the interface lifecycle.
type Scanner struct {
	iface  Interface
	handle Handle
	vendor VendorDB
}

func NewScanner(iface Interface, h Handle, vendor VendorDB) *Scanner {
	return &Scanner{iface: iface, handle: h, vendor: vendor}
}

// sweepProbeGap paces the ARP requests. Blasting a whole subnet at once lets the shared pcap
// handle drop replies that arrive during the send burst, which leaves only the fastest responder
// (the gateway) visible. A small gap keeps send and receive interleaved.
const sweepProbeGap = 3 * time.Millisecond

// Sweep ARP-requests every address in the subnet and collects replies until ctx is done.
// Callers should pass a context with a deadline (a few seconds is plenty on a home LAN).
func (s *Scanner) Sweep(ctx context.Context) ([]Device, error) {
	hosts, err := subnetHosts(s.iface.Subnet)
	if err != nil {
		return nil, err
	}

	table := NewTable()
	done := make(chan struct{})
	go s.readReplies(ctx, table, done)
	go s.enrichMDNS(ctx, table) // names and roles, concurrent with the ARP sweep

	for _, ip := range hosts {
		frame, err := BuildARPRequest(s.iface.IP, s.iface.MAC, ip)
		if err != nil {
			continue
		}
		// Two probes per host: ARP replies are unreliable and some hosts ignore the first.
		_ = s.handle.Send(frame)
		_ = s.handle.Send(frame)
		select {
		case <-ctx.Done():
			return s.finalize(table, done), nil
		case <-time.After(sweepProbeGap):
		}
	}

	<-ctx.Done()
	return s.finalize(table, done), nil
}

// finalize waits for the reply reader to stop, then adds best-effort reverse-DNS names and a
// vendor-based kind for any device still missing one.
func (s *Scanner) finalize(table *Table, done <-chan struct{}) []Device {
	<-done
	s.enrichReverseDNS(table)
	for _, d := range table.List() {
		if d.Kind == "" {
			table.MergeByIP(d.IP, "", kindFromVendor(d.Vendor), "")
		}
	}
	return table.List()
}

// enrichReverseDNS fills hostnames the other signals missed by asking the local resolver for the
// PTR record of each device, bounded by a short timeout and a small concurrency limit.
func (s *Scanner) enrichReverseDNS(table *Table) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, d := range table.List() {
		if d.Hostname != "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(dev Device) {
			defer wg.Done()
			defer func() { <-sem }()
			names, err := net.DefaultResolver.LookupAddr(ctx, dev.IP.String())
			if err == nil && len(names) > 0 {
				table.MergeByIP(dev.IP, strings.TrimSuffix(names[0], "."), "", "")
			}
		}(d)
	}
	wg.Wait()
}

// ResolveMAC returns the MAC for a single IP, used to learn the gateway's hardware address
// before spoofing. It blocks until a reply arrives or ctx is done.
func (s *Scanner) ResolveMAC(ctx context.Context, ip net.IP) (net.HardwareAddr, error) {
	frame, err := BuildARPRequest(s.iface.IP, s.iface.MAC, ip)
	if err != nil {
		return nil, err
	}
	if err := s.handle.Send(frame); err != nil {
		return nil, err
	}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("engine: timed out resolving %s", ip)
		default:
		}
		pkt, err := s.handle.Recv()
		if err != nil || pkt == nil {
			continue
		}
		arp, ok := arpReply(pkt)
		if !ok {
			continue
		}
		if net.IP(arp.SourceProtAddress).Equal(ip) {
			return net.HardwareAddr(arp.SourceHwAddress), nil
		}
	}
}

func (s *Scanner) readReplies(ctx context.Context, table *Table, done chan<- struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pkt, err := s.handle.Recv()
		if err != nil || pkt == nil {
			continue
		}
		arp, ok := arpSender(pkt)
		if !ok {
			continue
		}
		ip := net.IP(arp.SourceProtAddress)
		mac := net.HardwareAddr(arp.SourceHwAddress)
		if ip.Equal(s.iface.IP) || ip.Equal(net.IPv4zero) {
			continue
		}
		table.Upsert(Device{
			IP:       ip,
			MAC:      mac,
			Vendor:   s.vendor.Lookup(mac),
			LastSeen: time.Now(),
		})
	}
}

func arpReply(pkt gopacket.Packet) (*layers.ARP, bool) {
	l := pkt.Layer(layers.LayerTypeARP)
	if l == nil {
		return nil, false
	}
	arp, ok := l.(*layers.ARP)
	if !ok || arp.Operation != layers.ARPReply {
		return nil, false
	}
	return arp, true
}

// arpSender returns the sender of any ARP packet, request or reply. Harvesting requests too lets
// the scan learn devices passively from the ARP traffic a busy LAN already produces.
func arpSender(pkt gopacket.Packet) (*layers.ARP, bool) {
	l := pkt.Layer(layers.LayerTypeARP)
	if l == nil {
		return nil, false
	}
	arp, ok := l.(*layers.ARP)
	if !ok {
		return nil, false
	}
	return arp, true
}

// subnetHosts enumerates usable host addresses in n. It refuses subnets wider than /16 to
// avoid an unbounded sweep.
func subnetHosts(n *net.IPNet) ([]net.IP, error) {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("engine: only IPv4 subnets are supported")
	}
	if ones < 16 {
		return nil, fmt.Errorf("engine: subnet /%d is too large to sweep", ones)
	}

	base := n.IP.Mask(n.Mask).To4()
	count := 1 << uint(bits-ones)
	hosts := make([]net.IP, 0, count)
	for i := 1; i < count-1; i++ {
		ip := make(net.IP, 4)
		copy(ip, base)
		ip[0] += byte(i >> 24)
		ip[1] += byte(i >> 16)
		ip[2] += byte(i >> 8)
		ip[3] += byte(i)
		hosts = append(hosts, ip)
	}
	return hosts, nil
}
