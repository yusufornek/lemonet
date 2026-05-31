package engine

import (
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestBuildARPReply(t *testing.T) {
	senderIP := net.IPv4(192, 168, 1, 1)
	senderMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	targetIP := net.IPv4(192, 168, 1, 50)
	targetMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}

	frame, err := BuildARPReply(senderIP, senderMAC, targetIP, targetMAC)
	if err != nil {
		t.Fatalf("BuildARPReply: %v", err)
	}

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arpLayer := pkt.Layer(layers.LayerTypeARP)
	if arpLayer == nil {
		t.Fatal("no ARP layer in built frame")
	}
	arp := arpLayer.(*layers.ARP)

	if arp.Operation != layers.ARPReply {
		t.Errorf("operation = %d, want reply", arp.Operation)
	}
	if !net.IP(arp.SourceProtAddress).Equal(senderIP.To4()) {
		t.Errorf("sender IP = %v, want %v", net.IP(arp.SourceProtAddress), senderIP)
	}
	if net.HardwareAddr(arp.SourceHwAddress).String() != senderMAC.String() {
		t.Errorf("sender MAC = %v, want %v", net.HardwareAddr(arp.SourceHwAddress), senderMAC)
	}
	if !net.IP(arp.DstProtAddress).Equal(targetIP.To4()) {
		t.Errorf("target IP = %v, want %v", net.IP(arp.DstProtAddress), targetIP)
	}
}

func TestBuildARPRejectsIPv6(t *testing.T) {
	v6 := net.ParseIP("fe80::1")
	mac := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	if _, err := BuildARPReply(v6, mac, v6, mac); err == nil {
		t.Fatal("expected error for IPv6 address, got nil")
	}
}
