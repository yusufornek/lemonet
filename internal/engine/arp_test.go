package engine

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

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

func TestARPSenderRejectsMalformedAddressSizes(t *testing.T) {
	frame := rawARPFrame(3, 4)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	if _, ok := arpSender(pkt); ok {
		t.Fatal("arpSender accepted a malformed hardware address size")
	}
	if _, ok := arpReply(pkt); ok {
		t.Fatal("arpReply accepted a malformed hardware address size")
	}
}

func TestARPSenderRejectsUnexpectedOperations(t *testing.T) {
	frame := rawARPFrameWithOperation(6, 4, 99)
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)

	if _, ok := arpSender(pkt); ok {
		t.Fatal("arpSender accepted an unexpected ARP operation")
	}
}

func TestReadRepliesIgnoresOffSubnetSenders(t *testing.T) {
	_, subnet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	iface := Interface{
		Name:   "en0",
		IP:     net.IPv4(192, 168, 1, 10),
		MAC:    mustHardwareAddr(t, "00:11:22:33:44:aa"),
		Subnet: subnet,
	}
	offSubnet := net.IPv4(10, 0, 0, 9)
	inSubnet := net.IPv4(192, 168, 1, 50)
	offFrame, err := BuildARPReply(offSubnet, mustHardwareAddr(t, "00:11:22:33:44:bb"), iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}
	inFrame, err := BuildARPReply(inSubnet, mustHardwareAddr(t, "00:11:22:33:44:cc"), iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}

	table := NewTable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	scanner := NewScanner(iface, &packetQueueHandle{packets: []gopacket.Packet{
		gopacket.NewPacket(offFrame, layers.LayerTypeEthernet, gopacket.Default),
		gopacket.NewPacket(inFrame, layers.LayerTypeEthernet, gopacket.Default),
	}}, NopVendorDB{})
	go scanner.readReplies(ctx, table, done)

	waitForDevice(t, table, inSubnet)
	cancel()
	<-done
	if _, ok := table.GetByIP(offSubnet); ok {
		t.Fatal("off-subnet ARP sender was inserted into the discovery table")
	}
}

func TestReadRepliesRejectsEthernetSourceMismatch(t *testing.T) {
	iface := testInterface(t)
	deviceIP := net.IPv4(192, 168, 1, 50)
	senderMAC := mustHardwareAddr(t, "00:11:22:33:44:bb")
	frame, err := BuildARPReply(deviceIP, senderMAC, iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}
	copy(frame[6:12], mustHardwareAddr(t, "00:11:22:33:44:cc"))

	table := readARPFrames(t, iface, frame)
	if _, ok := table.GetByIP(deviceIP); ok {
		t.Fatal("ARP sender with mismatched Ethernet source was inserted into the discovery table")
	}
}

func TestReadRepliesKeepsFirstMACForDuplicateIP(t *testing.T) {
	iface := testInterface(t)
	deviceIP := net.IPv4(192, 168, 1, 50)
	firstMAC := mustHardwareAddr(t, "00:11:22:33:44:bb")
	secondMAC := mustHardwareAddr(t, "00:11:22:33:44:cc")
	first, err := BuildARPReply(deviceIP, firstMAC, iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildARPReply(deviceIP, secondMAC, iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}

	table := readARPFrames(t, iface, first, second)
	dev, ok := table.GetByIP(deviceIP)
	if !ok {
		t.Fatal("device was not inserted into the discovery table")
	}
	if dev.MAC.String() != firstMAC.String() {
		t.Fatalf("duplicate IP owner = %s, want %s", dev.MAC, firstMAC)
	}
	if devices := devicesWithIP(table, deviceIP); len(devices) != 1 {
		t.Fatalf("duplicate IP produced %d table entries: %+v", len(devices), devices)
	}
}

func TestReadRepliesLearnsIPv6SourceAddress(t *testing.T) {
	iface := testInterface(t)
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceIPv6 := net.ParseIP("2001:db8::50")
	dstIPv6 := net.ParseIP("2001:db8::1")
	deviceMAC := mustHardwareAddr(t, "00:11:22:33:44:bb")
	arpFrame, err := BuildARPReply(deviceIP, deviceMAC, iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}
	ipv6Frame := udp6Frame(t, deviceMAC, iface.MAC, deviceIPv6, dstIPv6, 53123, 443, []byte("hello"))

	table := readPackets(t, iface,
		gopacket.NewPacket(arpFrame, layers.LayerTypeEthernet, gopacket.Default),
		gopacket.NewPacket(ipv6Frame, layers.LayerTypeEthernet, gopacket.Default),
	)
	dev, ok := table.DeviceByV6(deviceIPv6)
	if !ok {
		t.Fatal("IPv6 source address was not associated with the device")
	}
	if !dev.IP.Equal(deviceIP) {
		t.Fatalf("IPv6 owner IPv4 = %s, want %s", dev.IP, deviceIP)
	}
}

func TestTableUpsertRecordsDeviceIPv6Addresses(t *testing.T) {
	table := NewTable()
	mac := mustHardwareAddr(t, "00:11:22:33:44:bb")
	ipv6 := net.ParseIP("2001:db8::50")

	table.Upsert(Device{
		IP:   net.IPv4(192, 168, 1, 50),
		MAC:  mac,
		IPv6: []net.IP{ipv6},
	})

	if _, ok := table.DeviceByV6(ipv6); !ok {
		t.Fatal("upserted IPv6 address was not associated with the device")
	}
}

func TestScannerProbeIPv6AllNodesSendsEchoRequest(t *testing.T) {
	iface := testInterface(t)
	iface.LinkLocal = net.ParseIP("fe80::211:22ff:fe33:44aa")
	handle := &packetQueueHandle{}
	scanner := NewScanner(iface, handle, NopVendorDB{})

	scanner.probeIPv6AllNodes()

	if len(handle.sent) != 1 {
		t.Fatalf("sent frames = %d, want 1 IPv6 probe", len(handle.sent))
	}
	pkt := gopacket.NewPacket(handle.sent[0], layers.LayerTypeEthernet, gopacket.Default)
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	if eth.DstMAC.String() != "33:33:00:00:00:01" {
		t.Fatalf("probe dst mac = %s, want all-nodes multicast", eth.DstMAC)
	}
	ip6 := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ip6.SrcIP.Equal(iface.LinkLocal) || !ip6.DstIP.Equal(allNodesIP) {
		t.Fatalf("probe IPv6 src/dst = %s -> %s, want %s -> %s", ip6.SrcIP, ip6.DstIP, iface.LinkLocal, allNodesIP)
	}
	if pkt.Layer(layers.LayerTypeICMPv6Echo) == nil {
		t.Fatal("probe does not contain an ICMPv6 echo request")
	}
}

func TestSpooferUpdateNowPoisonsImmediately(t *testing.T) {
	handle := &packetQueueHandle{}
	spoofer := NewSpoofer(handle, NewTable())
	target := Device{
		IP:  net.IPv4(192, 168, 1, 50),
		MAC: mustHardwareAddr(t, "00:11:22:33:44:55"),
	}

	spoofer.UpdateNow(SpoofConfig{
		Targets:    []Device{target},
		GatewayIP:  net.IPv4(192, 168, 1, 1),
		GatewayMAC: mustHardwareAddr(t, "00:aa:bb:cc:dd:ee"),
		SelfMAC:    mustHardwareAddr(t, "66:77:88:99:aa:bb"),
		FullDuplex: true,
	})

	if len(handle.sent) != 4 {
		t.Fatalf("poison frames = %d, want 4 immediate ARP poison frames", len(handle.sent))
	}
}

func TestResolveMACRejectsConflictingReplies(t *testing.T) {
	iface := testInterface(t)
	gatewayIP := net.IPv4(192, 168, 1, 1)
	first, err := BuildARPReply(gatewayIP, mustHardwareAddr(t, "00:11:22:33:44:55"), iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildARPReply(gatewayIP, mustHardwareAddr(t, "00:11:22:33:44:66"), iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(iface, &packetQueueHandle{packets: []gopacket.Packet{
		gopacket.NewPacket(first, layers.LayerTypeEthernet, gopacket.Default),
		gopacket.NewPacket(second, layers.LayerTypeEthernet, gopacket.Default),
	}}, NopVendorDB{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if mac, err := scanner.ResolveMAC(ctx, gatewayIP); err == nil {
		t.Fatalf("ResolveMAC returned %s, want conflicting reply error", mac)
	}
}

func TestResolveMACIgnoresRepliesTargetedElsewhere(t *testing.T) {
	iface := testInterface(t)
	gatewayIP := net.IPv4(192, 168, 1, 1)
	gatewayMAC := mustHardwareAddr(t, "00:11:22:33:44:55")
	wrongTarget, err := BuildARPReply(gatewayIP, mustHardwareAddr(t, "00:11:22:33:44:66"), net.IPv4(192, 168, 1, 99), mustHardwareAddr(t, "00:11:22:33:44:99"))
	if err != nil {
		t.Fatal(err)
	}
	good, err := BuildARPReply(gatewayIP, gatewayMAC, iface.IP, iface.MAC)
	if err != nil {
		t.Fatal(err)
	}
	scanner := NewScanner(iface, &packetQueueHandle{packets: []gopacket.Packet{
		gopacket.NewPacket(wrongTarget, layers.LayerTypeEthernet, gopacket.Default),
		gopacket.NewPacket(good, layers.LayerTypeEthernet, gopacket.Default),
	}}, NopVendorDB{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	mac, err := scanner.ResolveMAC(ctx, gatewayIP)
	if err != nil {
		t.Fatal(err)
	}
	if mac.String() != gatewayMAC.String() {
		t.Fatalf("ResolveMAC = %s, want %s", mac, gatewayMAC)
	}
}

func rawARPFrame(hwSize, protSize byte) []byte {
	return rawARPFrameWithOperation(hwSize, protSize, uint16(layers.ARPRequest))
}

func rawARPFrameWithOperation(hwSize, protSize byte, operation uint16) []byte {
	frame := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x08, 0x06,
		0x00, 0x01,
		0x08, 0x00,
		hwSize,
		protSize,
		byte(operation >> 8), byte(operation),
	}
	frame = append(frame, repeatedByte(0xaa, int(hwSize))...)
	frame = append(frame, repeatedByte(0xc0, int(protSize))...)
	frame = append(frame, repeatedByte(0xbb, int(hwSize))...)
	frame = append(frame, repeatedByte(0x00, int(protSize))...)
	return frame
}

func repeatedByte(v byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func waitForDevice(t *testing.T, table *Table, ip net.IP) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := table.GetByIP(ip); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("device %s was not inserted", ip)
		}
		time.Sleep(time.Millisecond)
	}
}

func readARPFrames(t *testing.T, iface Interface, frames ...[]byte) *Table {
	t.Helper()
	packets := make([]gopacket.Packet, 0, len(frames))
	for _, frame := range frames {
		packets = append(packets, gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))
	}
	return readPackets(t, iface, packets...)
}

func readPackets(t *testing.T, iface Interface, packets ...gopacket.Packet) *Table {
	t.Helper()
	table := NewTable()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	scanner := NewScanner(iface, &packetQueueHandle{packets: packets}, NopVendorDB{})
	go scanner.readReplies(ctx, table, done)
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	return table
}

func devicesWithIP(table *Table, ip net.IP) []Device {
	var out []Device
	for _, d := range table.List() {
		if d.IP.Equal(ip) {
			out = append(out, d)
		}
	}
	return out
}

func testInterface(t *testing.T) Interface {
	t.Helper()
	_, subnet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return Interface{
		Name:   "en0",
		IP:     net.IPv4(192, 168, 1, 10),
		MAC:    mustHardwareAddr(t, "00:11:22:33:44:aa"),
		Subnet: subnet,
	}
}

func mustHardwareAddr(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

type packetQueueHandle struct {
	packets []gopacket.Packet
	sent    [][]byte
}

func (h *packetQueueHandle) Send(frame []byte) error {
	h.sent = append(h.sent, append([]byte(nil), frame...))
	return nil
}

func (h *packetQueueHandle) Recv() (gopacket.Packet, error) {
	if len(h.packets) == 0 {
		time.Sleep(time.Millisecond)
		return nil, errors.New("empty")
	}
	pkt := h.packets[0]
	h.packets = h.packets[1:]
	return pkt, nil
}

func (h *packetQueueHandle) SetBPF(string) error { return nil }

func (h *packetQueueHandle) Close() error { return nil }
