package engine

import (
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
)

// readTimeout bounds a blocking Recv so the capture loops stay responsive to context
// cancellation instead of blocking forever when no packet arrives.
const readTimeout = 250 * time.Millisecond

// Handle is the capture/inject abstraction over a network interface. A pcap-backed
// implementation is the only path that works on Linux, macOS, and Windows alike.
type Handle interface {
	Send(frame []byte) error
	Recv() (gopacket.Packet, error)
	SetBPF(filter string) error
	Close() error
}

type pcapHandle struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

// OpenLive opens iface for live capture and injection. snaplen 65536 captures whole frames;
// a short read timeout keeps Recv responsive to context cancellation by the caller.
func OpenLive(iface string) (Handle, error) {
	h, err := pcap.OpenLive(iface, 65536, true, readTimeout)
	if err != nil {
		return nil, err
	}
	src := gopacket.NewPacketSource(h, h.LinkType())
	return &pcapHandle{handle: h, source: src}, nil
}

func (p *pcapHandle) Send(frame []byte) error {
	return p.handle.WritePacketData(frame)
}

func (p *pcapHandle) Recv() (gopacket.Packet, error) {
	return p.source.NextPacket()
}

func (p *pcapHandle) SetBPF(filter string) error {
	return p.handle.SetBPFFilter(filter)
}

func (p *pcapHandle) Close() error {
	p.handle.Close()
	return nil
}
