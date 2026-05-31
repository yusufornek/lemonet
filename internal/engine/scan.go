package engine

import (
	"context"
	"fmt"
	"net"
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

	for _, ip := range hosts {
		frame, err := BuildARPRequest(s.iface.IP, s.iface.MAC, ip)
		if err != nil {
			continue
		}
		if err := s.handle.Send(frame); err != nil {
			return nil, err
		}
	}

	<-ctx.Done()
	<-done
	return table.List(), nil
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
		if err != nil {
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
		if err != nil {
			continue
		}
		arp, ok := arpReply(pkt)
		if !ok {
			continue
		}
		ip := net.IP(arp.SourceProtAddress)
		mac := net.HardwareAddr(arp.SourceHwAddress)
		if ip.Equal(s.iface.IP) {
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
