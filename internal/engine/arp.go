package engine

import (
	"errors"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var errBadAddr = errors.New("engine: invalid IPv4 or MAC address")

// buildARP serializes an Ethernet frame carrying a single ARP message. operation is
// layers.ARPRequest or layers.ARPReply. The sender fields are what the recipient caches,
// which is how poisoning and restoration both work: only the sender values differ.
func buildARP(op uint16, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) ([]byte, error) {
	s4 := srcIP.To4()
	d4 := dstIP.To4()
	if s4 == nil || d4 == nil || len(srcMAC) != 6 || len(dstMAC) != 6 {
		return nil, errBadAddr
	}

	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         op,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: s4,
		DstHwAddress:      dstMAC,
		DstProtAddress:    d4,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BuildARPReply crafts an unsolicited ARP reply telling targetMAC that senderIP is at
// senderMAC. Used both to poison (senderMAC = our MAC) and to restore (senderMAC = the real
// owner's MAC).
func BuildARPReply(senderIP net.IP, senderMAC net.HardwareAddr, targetIP net.IP, targetMAC net.HardwareAddr) ([]byte, error) {
	return buildARP(layers.ARPReply, senderMAC, targetMAC, senderIP, targetIP)
}

// BuildARPRequest crafts a broadcast ARP request asking who has targetIP. Used by the scanner
// to sweep a subnet.
func BuildARPRequest(senderIP net.IP, senderMAC net.HardwareAddr, targetIP net.IP) ([]byte, error) {
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	return buildARP(layers.ARPRequest, senderMAC, broadcast, senderIP, targetIP)
}
