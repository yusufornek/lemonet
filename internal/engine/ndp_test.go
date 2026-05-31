package engine

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestBuildNeighborAdvertisement(t *testing.T) {
	ourMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	devMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}
	gwLL := net.ParseIP("fe80::1")

	frame, err := BuildNeighborAdvertisement(ourMAC, devMAC, gwLL, gwLL, ourMAC)
	if err != nil {
		t.Fatalf("BuildNeighborAdvertisement: %v", err)
	}

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	l := pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement)
	if l == nil {
		t.Fatal("no neighbor advertisement layer")
	}
	na := l.(*layers.ICMPv6NeighborAdvertisement)
	if !na.TargetAddress.Equal(gwLL) {
		t.Errorf("target = %v, want %v", na.TargetAddress, gwLL)
	}
	var tlla net.HardwareAddr
	for _, opt := range na.Options {
		if opt.Type == layers.ICMPv6OptTargetAddress {
			tlla = net.HardwareAddr(opt.Data)
		}
	}
	if tlla.String() != ourMAC.String() {
		t.Errorf("TLLA = %v, want %v", tlla, ourMAC)
	}
}

func TestBuildRouterSolicitation(t *testing.T) {
	ourMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	frame, err := BuildRouterSolicitation(ourMAC, net.ParseIP("fe80::abcd"))
	if err != nil {
		t.Fatalf("BuildRouterSolicitation: %v", err)
	}
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if pkt.Layer(layers.LayerTypeICMPv6RouterSolicitation) == nil {
		t.Fatal("no router solicitation layer")
	}
}

func TestLinkLocalFromMAC(t *testing.T) {
	mac := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	ll := linkLocalFromMAC(mac)
	if !ll.IsLinkLocalUnicast() {
		t.Errorf("derived %v is not link-local", ll)
	}
}
