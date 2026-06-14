package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/miekg/dns"
)

func TestScheduleSendHonorsContextCancel(t *testing.T) {
	h := newRecordHandle()
	r := NewRelay(h, Interface{}, nil, nil, NewTable(), nil)
	ctx, cancel := context.WithCancel(context.Background())

	r.scheduleSend(ctx, 20*time.Millisecond, []byte{1, 2, 3})
	cancel()

	select {
	case <-h.sent:
		t.Fatal("canceled delayed send should not forward")
	case <-time.After(60 * time.Millisecond):
	}
}

func TestScheduleSendForwardsAfterDelay(t *testing.T) {
	h := newRecordHandle()
	r := NewRelay(h, Interface{}, nil, nil, NewTable(), nil)

	r.scheduleSend(context.Background(), time.Millisecond, []byte{1, 2, 3})

	select {
	case got := <-h.sent:
		if string(got) != string([]byte{1, 2, 3}) {
			t.Fatalf("sent frame = %v", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("delayed send did not forward")
	}
}

func TestRelayInjectsUDPReplyPayload(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dnsIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, deviceMAC, selfMAC, deviceIP, dnsIP, 53123, 53, dnsQueryPayload(t, "blocked.example"))
	refusal, err := dnsrefusal(dnsQueryPayload(t, "blocked.example"))
	if err != nil {
		t.Fatal(err)
	}

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowReply, Payload: refusal}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertUDPFrame(t, sent, selfMAC, deviceMAC, dnsIP, deviceIP, 53, 53123, dns.RcodeNameError, false)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay did not inject DNS reply")
	}
}

func TestRelayRejectsFilteredTCPUploadWithReset(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	serverIP := net.IPv4(142, 250, 72, 206)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	payload := []byte("tls-client-hello")
	frame := tcpFrame(t, deviceMAC, selfMAC, deviceIP, serverIP, 53123, 443, 1000, 5000, true, true, payload)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertTCPResetFrame(t, sent, selfMAC, deviceMAC, serverIP, deviceIP, 443, 53123, 5000, 1000+uint32(len(payload)))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked TCP upload with a reset")
	}
	select {
	case sent := <-h.sent:
		assertTCPResetFrame(t, sent, selfMAC, gwMAC, deviceIP, serverIP, 53123, 443, 1000, 5000)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked TCP upload with a remote-side reset")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 {
		t.Fatalf("stats = %+v, want one dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayPassesIPContextToInspector(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	serverIP := net.IPv4(142, 250, 72, 206)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	payload := []byte("tls-client-hello")
	frame := tcpFrame(t, deviceMAC, selfMAC, deviceIP, serverIP, 53123, 443, 1000, 5000, true, true, payload)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(contextFlowInspectorFunc(func(ctx FlowContext) FlowAction {
		if ctx.Device.String() != "192.168.1.50" || ctx.Direction != Upload || ctx.UDP {
			return FlowAction{}
		}
		if ctx.SrcIP.String() != "192.168.1.50" || ctx.DstIP.String() != "142.250.72.206" {
			return FlowAction{}
		}
		if ctx.SrcPort != 53123 || ctx.DstPort != 443 || string(ctx.Payload) != string(payload) {
			return FlowAction{}
		}
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertTCPResetFrame(t, sent, selfMAC, deviceMAC, serverIP, deviceIP, 443, 53123, 5000, 1000+uint32(len(payload)))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should pass IP context to inspector and reject the flow")
	}
}

func TestRelayRejectsFilteredUDPUploadWithICMPUnreachable(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	serverIP := net.IPv4(142, 250, 72, 206)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, deviceMAC, selfMAC, deviceIP, serverIP, 53123, 443, []byte("quic-initial"))

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv4UnreachableFrame(t, sent, selfMAC, deviceMAC, serverIP, deviceIP)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked UDP upload with ICMP unreachable")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 {
		t.Fatalf("stats = %+v, want one dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayRejectsFilteredFragmentedUDPUploadWithICMPUnreachable(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	serverIP := net.IPv4(142, 250, 72, 206)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrameWithFlags(t, deviceMAC, selfMAC, deviceIP, serverIP, 53123, 443, []byte("quic-initial"), layers.IPv4MoreFragments)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv4UnreachableFrame(t, sent, selfMAC, deviceMAC, serverIP, deviceIP)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject filtered fragmented UDP upload with ICMP unreachable")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Fragments != 0 || stats.Forwarded != 0 {
		t.Fatalf("stats = %+v, want one filtered drop with ICMP rejection", stats)
	}
}

func TestRelayRejectsFilteredUDPDownloadWithICMPUnreachable(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	serverIP := net.IPv4(142, 250, 72, 206)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, gwMAC, selfMAC, serverIP, deviceIP, 443, 53123, []byte("quic-payload"))

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv4UnreachableFrame(t, sent, selfMAC, deviceMAC, serverIP, deviceIP)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked UDP download with ICMP unreachable")
	}
	select {
	case sent := <-h.sent:
		assertICMPv4UnreachableFrame(t, sent, selfMAC, gwMAC, deviceIP, serverIP)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked UDP download with a remote-side ICMP unreachable")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 {
		t.Fatalf("stats = %+v, want one dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayRejectsFilteredTCPDownloadWithReset(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	serverIP := net.IPv4(142, 250, 72, 206)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	payload := []byte("tls-application-data")
	frame := tcpFrame(t, gwMAC, selfMAC, serverIP, deviceIP, 443, 53123, 7000, 1200, true, true, payload)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertTCPResetFrame(t, sent, selfMAC, deviceMAC, serverIP, deviceIP, 443, 53123, 7000, 1200)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked TCP download with a reset")
	}
	select {
	case sent := <-h.sent:
		assertTCPResetFrame(t, sent, selfMAC, gwMAC, deviceIP, serverIP, 53123, 443, 1200, 7000+uint32(len(payload)))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked TCP download with a remote-side reset")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 {
		t.Fatalf("stats = %+v, want one dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayRejectsFilteredIPv6TCPUploadWithReset(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceIP6 := net.ParseIP("fe80::211:22ff:fe33:4455")
	serverIP6 := net.ParseIP("2a00:1450:4009:80b::200e")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	payload := []byte("tls-client-hello")
	frame := tcp6Frame(t, deviceMAC, selfMAC, deviceIP6, serverIP6, 53123, 443, 1000, 5000, true, true, payload)

	table := tableWithDevice(deviceIP, deviceMAC)
	table.RecordV6(deviceMAC, deviceIP6)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertTCPReset6Frame(t, sent, selfMAC, deviceMAC, serverIP6, deviceIP6, 443, 53123, 5000, 1000+uint32(len(payload)))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked IPv6 TCP upload with a reset")
	}
	select {
	case sent := <-h.sent:
		assertTCPReset6Frame(t, sent, selfMAC, gwMAC, deviceIP6, serverIP6, 53123, 443, 1000, 5000)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked IPv6 TCP upload with a remote-side reset")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 || stats.IPv6 != 1 {
		t.Fatalf("stats = %+v, want one IPv6 dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayRejectsFilteredIPv6TCPDownloadWithReset(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceIP6 := net.ParseIP("fe80::211:22ff:fe33:4455")
	serverIP6 := net.ParseIP("2a00:1450:4009:80b::200e")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	payload := []byte("tls-application-data")
	frame := tcp6Frame(t, gwMAC, selfMAC, serverIP6, deviceIP6, 443, 53123, 7000, 1200, true, true, payload)

	table := tableWithDevice(deviceIP, deviceMAC)
	table.RecordV6(deviceMAC, deviceIP6)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertTCPReset6Frame(t, sent, selfMAC, deviceMAC, serverIP6, deviceIP6, 443, 53123, 7000, 1200)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked IPv6 TCP download with a reset")
	}
	select {
	case sent := <-h.sent:
		assertTCPReset6Frame(t, sent, selfMAC, gwMAC, deviceIP6, serverIP6, 53123, 443, 1200, 7000+uint32(len(payload)))
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked IPv6 TCP download with a remote-side reset")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 || stats.IPv6 != 1 {
		t.Fatalf("stats = %+v, want one IPv6 dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayRejectsFilteredIPv6UDPDownloadWithICMPUnreachable(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceIP6 := net.ParseIP("fe80::211:22ff:fe33:4455")
	serverIP6 := net.ParseIP("2a00:1450:4009:80b::200e")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udp6Frame(t, gwMAC, selfMAC, serverIP6, deviceIP6, 443, 53123, []byte("quic-payload"))

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	table := tableWithDevice(deviceIP, deviceMAC)
	table.RecordV6(deviceMAC, deviceIP6)
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv6UnreachableFrame(t, sent, selfMAC, deviceMAC, serverIP6, deviceIP6)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked IPv6 UDP download with ICMP unreachable")
	}
	select {
	case sent := <-h.sent:
		assertICMPv6UnreachableFrame(t, sent, selfMAC, gwMAC, deviceIP6, serverIP6)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked IPv6 UDP download with a remote-side ICMP unreachable")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 || stats.IPv6 != 1 {
		t.Fatalf("stats = %+v, want one IPv6 dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayRejectsFilteredIPv6UDPUploadWithICMPUnreachable(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceIP6 := net.ParseIP("fe80::211:22ff:fe33:4455")
	serverIP6 := net.ParseIP("2a00:1450:4009:80b::200e")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udp6Frame(t, deviceMAC, selfMAC, deviceIP6, serverIP6, 53123, 443, []byte("quic-initial"))

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv6UnreachableFrame(t, sent, selfMAC, deviceMAC, serverIP6, deviceIP6)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject blocked IPv6 UDP upload with ICMP unreachable")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Forwarded != 0 || stats.IPv6 != 1 {
		t.Fatalf("stats = %+v, want one IPv6 dropped original packet and no forwarded original traffic", stats)
	}
}

func TestRelayRejectsFilteredIPv6FragmentedUDPUploadWithICMPUnreachable(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceIP6 := net.ParseIP("fe80::211:22ff:fe33:4455")
	serverIP6 := net.ParseIP("2a00:1450:4009:80b::200e")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udp6FragmentFrame(t, deviceMAC, selfMAC, deviceIP6, serverIP6, 53123, 443, []byte("quic-initial"))

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowDrop}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv6UnreachableFrame(t, sent, selfMAC, deviceMAC, serverIP6, deviceIP6)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay should reject filtered IPv6 fragmented UDP upload with ICMP unreachable")
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Fragments != 0 || stats.Forwarded != 0 || stats.IPv6 != 1 {
		t.Fatalf("stats = %+v, want one filtered IPv6 drop with ICMP rejection", stats)
	}
}

func TestRelayStatsRecordPerDeviceReplyWithoutPayloadDetails(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dnsIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	query := dnsQueryPayload(t, "blocked.example")
	frame := udpFrame(t, deviceMAC, selfMAC, deviceIP, dnsIP, 53123, 53, query)
	refusal, err := dnsrefusal(query)
	if err != nil {
		t.Fatal(err)
	}

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowReply, Payload: refusal}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case <-h.sent:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay did not inject DNS reply")
	}
	stats := r.Stats()
	if stats.Replies != 1 || stats.Forwarded != 1 || stats.Received != 1 {
		t.Fatalf("aggregate stats = %+v, want one received, forwarded reply", stats)
	}
	if len(stats.Devices) != 1 {
		t.Fatalf("device stats len = %d, want 1", len(stats.Devices))
	}
	deviceStats := stats.Devices[0]
	if deviceStats.Device != "192.168.1.50" || deviceStats.Replies != 1 || deviceStats.Forwarded != 1 || deviceStats.Received != 1 {
		t.Fatalf("device stats = %+v, want one received, forwarded reply for device", deviceStats)
	}
	if len(stats.Recent) != 1 {
		t.Fatalf("recent events len = %d, want 1", len(stats.Recent))
	}
	event := stats.Recent[0]
	if event.Device != "192.168.1.50" || event.Direction != "upload" || event.Action != "reply" || event.Protocol != "udp" || event.DstPort != 53 {
		t.Fatalf("recent event = %+v, want DNS reply upload event", event)
	}
	body, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("blocked.example")) || bytes.Contains(body, query) {
		t.Fatalf("relay stats leaked DNS query details: %s", body)
	}
}

func TestRelayStatsRecordFragmentDropByDevice(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dnsIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	query := dnsQueryPayload(t, "blocked.example")
	frame := udpFrameWithFlags(t, deviceMAC, selfMAC, deviceIP, dnsIP, 53123, 53, query, layers.IPv4MoreFragments)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case <-h.sent:
		t.Fatal("fragmented packet should not be forwarded")
	case <-time.After(60 * time.Millisecond):
	}
	stats := r.Stats()
	if stats.Dropped != 1 || stats.Fragments != 1 {
		t.Fatalf("aggregate stats = %+v, want one fragment drop", stats)
	}
	if len(stats.Devices) != 1 {
		t.Fatalf("device stats len = %d, want 1", len(stats.Devices))
	}
	deviceStats := stats.Devices[0]
	if deviceStats.Device != "192.168.1.50" || deviceStats.Dropped != 1 || deviceStats.Fragments != 1 {
		t.Fatalf("device stats = %+v, want one fragment drop for device", deviceStats)
	}
	if len(stats.Recent) != 1 {
		t.Fatalf("recent events len = %d, want 1", len(stats.Recent))
	}
	event := stats.Recent[0]
	if event.Device != "192.168.1.50" || event.Action != "drop" || event.Reason != "fragment" || event.Protocol != "udp" || event.DstPort != 53 {
		t.Fatalf("recent event = %+v, want fragment drop event", event)
	}
	body, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("blocked.example")) || bytes.Contains(body, query) {
		t.Fatalf("relay stats leaked packet details: %s", body)
	}
}

func TestRelayStatsDoNotForwardOnSendError(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dnsIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	query := dnsQueryPayload(t, "blocked.example")
	frame := udpFrame(t, deviceMAC, selfMAC, deviceIP, dnsIP, 53123, 53, query)
	refusal, err := dnsrefusal(query)
	if err != nil {
		t.Fatal(err)
	}

	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(errorSendHandle{err: errors.New("send failed")}, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowReply, Payload: refusal}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	stats := r.Stats()
	if stats.Forwarded != 0 || stats.Replies != 0 || stats.SendErrors != 1 {
		t.Fatalf("aggregate stats = %+v, want one send error and no successful forward", stats)
	}
	if len(stats.Devices) != 1 {
		t.Fatalf("device stats len = %d, want 1", len(stats.Devices))
	}
	deviceStats := stats.Devices[0]
	if deviceStats.Device != "192.168.1.50" || deviceStats.Forwarded != 0 || deviceStats.Replies != 0 || deviceStats.SendErrors != 1 {
		t.Fatalf("device stats = %+v, want one send error and no successful forward", deviceStats)
	}
	if len(stats.Recent) != 1 {
		t.Fatalf("recent events len = %d, want 1", len(stats.Recent))
	}
	event := stats.Recent[0]
	if event.Action != "error" || event.Reason != "send" || event.Protocol != "udp" || event.DstPort != 53 {
		t.Fatalf("recent event = %+v, want send error event", event)
	}
	body, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("blocked.example")) || bytes.Contains(body, query) {
		t.Fatalf("relay stats leaked packet details: %s", body)
	}
}

func TestRelayStatsRecordDelayedForwardByDevice(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dstIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, deviceMAC, selfMAC, deviceIP, dstIP, 53123, 443, []byte("payload"))

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), deciderFunc(func(_ netip.Addr, _ Direction, _ int) (bool, time.Duration) {
		return false, time.Millisecond
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	if stats := r.Stats(); stats.Shaped != 1 || stats.Forwarded != 0 {
		t.Fatalf("queued stats = %+v, want one shaped packet and no forward yet", stats)
	}
	select {
	case <-h.sent:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("delayed packet was not forwarded")
	}
	stats := waitRelayStats(t, r, func(stats RelayStats) bool {
		return stats.Forwarded == 1 && len(stats.Devices) == 1 && stats.Devices[0].Forwarded == 1
	})
	if stats.Shaped != 1 || stats.Forwarded != 1 {
		t.Fatalf("final stats = %+v, want one shaped forwarded packet", stats)
	}
	if len(stats.Devices) != 1 {
		t.Fatalf("device stats len = %d, want 1", len(stats.Devices))
	}
	deviceStats := stats.Devices[0]
	if deviceStats.Device != "192.168.1.50" || deviceStats.Shaped != 1 || deviceStats.Forwarded != 1 {
		t.Fatalf("device stats = %+v, want one shaped forwarded packet", deviceStats)
	}
	if len(stats.Recent) != 2 {
		t.Fatalf("recent events len = %d, want shape and forward events", len(stats.Recent))
	}
	if stats.Recent[0].Action != "shape" || stats.Recent[1].Action != "forward" {
		t.Fatalf("recent events = %+v, want shape then forward", stats.Recent)
	}
}

func waitRelayStats(t *testing.T, r *Relay, ready func(RelayStats) bool) RelayStats {
	t.Helper()
	deadline := time.Now().Add(100 * time.Millisecond)
	for {
		stats := r.Stats()
		if ready(stats) {
			return stats
		}
		if time.Now().After(deadline) {
			t.Fatalf("relay stats did not reach expected state: %+v", stats)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestRelayStatsKeepBoundedRecentEvents(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dnsIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrameWithFlags(t, deviceMAC, selfMAC, deviceIP, dnsIP, 53123, 53, dnsQueryPayload(t, "blocked.example"), layers.IPv4MoreFragments)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	for i := 0; i < maxRelayEvents+7; i++ {
		r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))
	}

	stats := r.Stats()
	if stats.Fragments != maxRelayEvents+7 {
		t.Fatalf("fragments = %d, want %d", stats.Fragments, maxRelayEvents+7)
	}
	if len(stats.Recent) != maxRelayEvents {
		t.Fatalf("recent events len = %d, want %d", len(stats.Recent), maxRelayEvents)
	}
}

func TestRelayRewritesUDPPayload(t *testing.T) {
	dnsIP := net.IPv4(8, 8, 8, 8)
	device := engineDevice(t)
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	originalPayload := httpsResponsePayload(t, true)
	rewrittenPayload := httpsResponsePayload(t, false)
	frame := udpFrame(t, gwMAC, selfMAC, dnsIP, device.IP, 53, 53123, originalPayload)

	table := NewTable()
	table.Upsert(device)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowReplace, Payload: rewrittenPayload}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertUDPFrame(t, sent, selfMAC, device.MAC, dnsIP, device.IP, 53, 53123, dns.RcodeSuccess, false)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay did not forward rewritten DNS response")
	}
}

func TestRelayClassifiesGatewayDNSAsUpload(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	gatewayIP := net.IPv4(192, 168, 1, 1)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, deviceMAC, selfMAC, deviceIP, gatewayIP, 53123, 53, dnsQueryPayload(t, "blocked.example"))
	refusal, err := dnsrefusal(dnsQueryPayload(t, "blocked.example"))
	if err != nil {
		t.Fatal(err)
	}

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, gatewayIP, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	var gotDir Direction
	var gotDevice netip.Addr
	r.SetInspector(flowInspectorFunc(func(device netip.Addr, dir Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		gotDir = dir
		gotDevice = device
		return FlowAction{Kind: FlowReply, Payload: refusal}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	if gotDir != Upload || gotDevice.String() != "192.168.1.50" {
		t.Fatalf("gateway DNS classified as %v for %s, want upload for device", gotDir, gotDevice)
	}
	select {
	case sent := <-h.sent:
		assertUDPFrame(t, sent, selfMAC, deviceMAC, gatewayIP, deviceIP, 53, 53123, dns.RcodeNameError, false)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay did not inject gateway DNS reply")
	}
}

func TestRelayRoutesIPv6GatewayLinkLocalDNSAsUpload(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceLL := net.ParseIP("fe80::211:22ff:fe33:4455")
	gatewayLL := net.ParseIP("fe80::1")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udp6Frame(t, deviceMAC, selfMAC, deviceLL, gatewayLL, 53123, 53, dnsQueryPayload(t, "blocked.example"))

	table := tableWithDevice(deviceIP, deviceMAC)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	var gotDir Direction
	var gotDevice netip.Addr
	r.SetInspector(flowInspectorFunc(func(device netip.Addr, dir Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		gotDir = dir
		gotDevice = device
		return FlowAction{}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	if gotDir != Upload || gotDevice.String() != "192.168.1.50" {
		t.Fatalf("gateway IPv6 DNS classified as %v for %s, want upload for device", gotDir, gotDevice)
	}
	if _, ok := table.DeviceByV6(deviceLL); !ok {
		t.Fatal("device link-local IPv6 was not learned")
	}
	select {
	case sent := <-h.sent:
		assertEthernetFrame(t, sent, selfMAC, gwMAC)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay did not forward IPv6 gateway DNS query")
	}
}

func TestRelayNotifiesWhenIPv6AddressIsLearned(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceIP6 := net.ParseIP("2001:db8::50")
	serverIP6 := net.ParseIP("2a00:1450:4009:80b::200e")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udp6Frame(t, deviceMAC, selfMAC, deviceIP6, serverIP6, 53123, 443, []byte("quic-initial"))

	table := tableWithDevice(deviceIP, deviceMAC)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	var learned int
	r.SetIPv6LearnedHook(func() { learned++ })

	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	r.handlePacket(context.Background(), pkt)
	r.handlePacket(context.Background(), pkt)

	if learned != 1 {
		t.Fatalf("IPv6 learned hook calls = %d, want 1", learned)
	}
}

func TestRelayRoutesIPv6GatewayLinkLocalDNSResponseAsDownload(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	deviceLL := net.ParseIP("fe80::211:22ff:fe33:4455")
	gatewayLL := net.ParseIP("fe80::1")
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udp6Frame(t, gwMAC, selfMAC, gatewayLL, deviceLL, 53, 53123, dnsQueryPayload(t, "blocked.example"))

	table := tableWithDevice(deviceIP, deviceMAC)
	table.RecordV6(deviceMAC, deviceLL)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	var gotDir Direction
	var gotDevice netip.Addr
	r.SetInspector(flowInspectorFunc(func(device netip.Addr, dir Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		gotDir = dir
		gotDevice = device
		return FlowAction{}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	if gotDir != Download || gotDevice.String() != "192.168.1.50" {
		t.Fatalf("gateway IPv6 DNS response classified as %v for %s, want download for device", gotDir, gotDevice)
	}
	select {
	case sent := <-h.sent:
		assertEthernetFrame(t, sent, selfMAC, deviceMAC)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("relay did not forward IPv6 gateway DNS response")
	}
}

func TestRelayDropsIPv4UploadWhenSourceIPDoesNotMatchKnownMAC(t *testing.T) {
	device := engineDevice(t)
	spoofedIP := net.IPv4(192, 168, 1, 99)
	dstIP := net.IPv4(8, 8, 8, 8)
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, device.MAC, selfMAC, spoofedIP, dstIP, 53123, 443, []byte("payload"))

	table := NewTable()
	table.Upsert(device)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, deciderFunc(func(netip.Addr, Direction, int) (bool, time.Duration) {
		return false, 0
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case <-h.sent:
		t.Fatal("known MAC with mismatched source IP should not be forwarded")
	case <-time.After(60 * time.Millisecond):
	}
	stats := r.Stats()
	if stats.Received != 0 || stats.Forwarded != 0 || stats.Dropped != 0 {
		t.Fatalf("stats = %+v, want unrouted frame ignored", stats)
	}
}

func TestRelayDropsUnknownSourceMACIPv4Upload(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 80)
	dstIP := net.IPv4(8, 8, 8, 8)
	unknownMAC := mustRelayMAC(t, "00:11:22:33:44:80")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, unknownMAC, selfMAC, deviceIP, dstIP, 53123, 443, []byte("payload"))

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, NewTable(), nil)
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case <-h.sent:
		t.Fatal("unknown source MAC upload should not be forwarded")
	case <-time.After(60 * time.Millisecond):
	}
	stats := r.Stats()
	if stats.Received != 0 || stats.Forwarded != 0 || stats.Dropped != 0 {
		t.Fatalf("stats = %+v, want route to decline unknown source MAC without forwarding", stats)
	}
}

func TestRelayDropsUnknownSourceMACIPv4LocalForward(t *testing.T) {
	victim := engineDevice(t)
	unknownIP := net.IPv4(192, 168, 1, 80)
	unknownMAC := mustRelayMAC(t, "00:11:22:33:44:80")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrame(t, unknownMAC, selfMAC, unknownIP, victim.IP, 53123, 443, []byte("payload"))

	table := NewTable()
	table.Upsert(victim)
	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, table, nil)
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case <-h.sent:
		t.Fatal("unknown source MAC local frame should not be forwarded")
	case <-time.After(60 * time.Millisecond):
	}
	stats := r.Stats()
	if stats.Received != 0 || stats.Forwarded != 0 || stats.Dropped != 0 {
		t.Fatalf("stats = %+v, want route to decline unknown local source MAC without forwarding", stats)
	}
}

func TestRelayRejectsUnsafeDNSReplyOnIPv4Fragments(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dnsIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrameWithFlags(t, deviceMAC, selfMAC, deviceIP, dnsIP, 53123, 53, dnsQueryPayload(t, "blocked.example"), layers.IPv4MoreFragments)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowReply, Payload: dnsQueryPayload(t, "blocked.example")}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv4UnreachableFrame(t, sent, selfMAC, deviceMAC, dnsIP, deviceIP)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("fragmented DNS reply path should reject with ICMP unreachable")
	}
}

func TestRelayRejectsUnsafeDNSRewriteOnIPv4Fragments(t *testing.T) {
	deviceIP := net.IPv4(192, 168, 1, 50)
	dnsIP := net.IPv4(8, 8, 8, 8)
	deviceMAC := mustRelayMAC(t, "00:11:22:33:44:55")
	selfMAC := mustRelayMAC(t, "66:77:88:99:aa:bb")
	gwMAC := mustRelayMAC(t, "00:aa:bb:cc:dd:ee")
	frame := udpFrameWithFlags(t, gwMAC, selfMAC, dnsIP, deviceIP, 53, 53123, dnsQueryPayload(t, "blocked.example"), layers.IPv4MoreFragments)

	h := newRecordHandle()
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")
	r := NewRelay(h, Interface{MAC: selfMAC, Subnet: subnet}, nil, gwMAC, tableWithDevice(deviceIP, deviceMAC), nil)
	r.SetInspector(flowInspectorFunc(func(_ netip.Addr, _ Direction, _ bool, _ uint16, _ uint16, _ []byte) FlowAction {
		return FlowAction{Kind: FlowReplace, Payload: dnsQueryPayload(t, "blocked.example")}
	}))
	r.handlePacket(context.Background(), gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default))

	select {
	case sent := <-h.sent:
		assertICMPv4UnreachableFrame(t, sent, selfMAC, deviceMAC, dnsIP, deviceIP)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("fragmented DNS rewrite path should reject with ICMP unreachable")
	}
	select {
	case sent := <-h.sent:
		assertICMPv4UnreachableFrame(t, sent, selfMAC, gwMAC, deviceIP, dnsIP)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("fragmented DNS rewrite path should reject remote side with ICMP unreachable")
	}
}

type flowInspectorFunc func(netip.Addr, Direction, bool, uint16, uint16, []byte) FlowAction

func (f flowInspectorFunc) InspectFlow(device netip.Addr, dir Direction, udp bool, srcPort, dstPort uint16, payload []byte) FlowAction {
	return f(device, dir, udp, srcPort, dstPort, payload)
}

type contextFlowInspectorFunc func(FlowContext) FlowAction

func (f contextFlowInspectorFunc) InspectFlow(netip.Addr, Direction, bool, uint16, uint16, []byte) FlowAction {
	return FlowAction{}
}

func (f contextFlowInspectorFunc) InspectFlowContext(ctx FlowContext) FlowAction {
	return f(ctx)
}

type deciderFunc func(netip.Addr, Direction, int) (bool, time.Duration)

func (f deciderFunc) Decide(device netip.Addr, dir Direction, length int) (bool, time.Duration) {
	return f(device, dir, length)
}

type recordHandle struct {
	sent chan []byte
}

func newRecordHandle() *recordHandle {
	return &recordHandle{sent: make(chan []byte, 4)}
}

func (h *recordHandle) Send(frame []byte) error {
	h.sent <- append([]byte(nil), frame...)
	return nil
}

func (h *recordHandle) Recv() (gopacket.Packet, error) { return nil, errors.New("empty") }

func (h *recordHandle) SetBPF(string) error { return nil }

func (h *recordHandle) Close() error { return nil }

type errorSendHandle struct {
	err error
}

func (h errorSendHandle) Send([]byte) error { return h.err }

func (h errorSendHandle) Recv() (gopacket.Packet, error) { return nil, errors.New("empty") }

func (h errorSendHandle) SetBPF(string) error { return nil }

func (h errorSendHandle) Close() error { return nil }

func udpFrame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	return udpFrameWithFlags(t, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, payload, 0)
}

func udpFrameWithFlags(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte, flags layers.IPv4Flag) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolUDP, Flags: flags}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func udp6Frame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: srcIP, DstIP: dstIP, NextHeader: layers.IPProtocolUDP}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func udp6FragmentFrame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: srcIP, DstIP: dstIP, NextHeader: layers.IPProtocolIPv6Fragment}
	frag := &layers.IPv6Fragment{NextHeader: layers.IPProtocolUDP, MoreFragments: true, Identification: 1}
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	checksumIP := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: srcIP, DstIP: dstIP, NextHeader: layers.IPProtocolUDP}
	if err := udp.SetNetworkLayerForChecksum(checksumIP); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, frag, udp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tcp6Frame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, ackFlag, pshFlag bool, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv6}
	ip := &layers.IPv6{Version: 6, HopLimit: 64, SrcIP: srcIP, DstIP: dstIP, NextHeader: layers.IPProtocolTCP}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		ACK:     ackFlag,
		PSH:     pshFlag,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func tcpFrame(t *testing.T, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, ackFlag, pshFlag bool, payload []byte) []byte {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: srcMAC, DstMAC: dstMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, TTL: 64, SrcIP: srcIP, DstIP: dstIP, Protocol: layers.IPProtocolTCP}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		ACK:     ackFlag,
		PSH:     pshFlag,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, serializeOptions, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func assertEthernetFrame(t *testing.T, frame []byte, srcMAC, dstMAC net.HardwareAddr) {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		t.Fatal("missing ethernet layer")
	}
	eth := ethLayer.(*layers.Ethernet)
	if !bytes.Equal(eth.SrcMAC, srcMAC) || !bytes.Equal(eth.DstMAC, dstMAC) {
		t.Fatalf("ethernet = %s -> %s, want %s -> %s", eth.SrcMAC, eth.DstMAC, srcMAC, dstMAC)
	}
}

func assertTCPResetFrame(t *testing.T, frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32) {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	assertEthernetFrame(t, frame, srcMAC, dstMAC)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip.SrcIP.Equal(srcIP) || !ip.DstIP.Equal(dstIP) {
		t.Fatalf("ip = %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, srcIP, dstIP)
	}
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if uint16(tcp.SrcPort) != srcPort || uint16(tcp.DstPort) != dstPort {
		t.Fatalf("tcp = %d -> %d, want %d -> %d", tcp.SrcPort, tcp.DstPort, srcPort, dstPort)
	}
	if !tcp.RST || !tcp.ACK || tcp.SYN || tcp.FIN {
		t.Fatalf("tcp flags RST=%v ACK=%v SYN=%v FIN=%v, want RST+ACK only", tcp.RST, tcp.ACK, tcp.SYN, tcp.FIN)
	}
	if tcp.Seq != seq || tcp.Ack != ack {
		t.Fatalf("tcp seq/ack = %d/%d, want %d/%d", tcp.Seq, tcp.Ack, seq, ack)
	}
}

func assertTCPReset6Frame(t *testing.T, frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32) {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	assertEthernetFrame(t, frame, srcMAC, dstMAC)
	ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ip.SrcIP.Equal(srcIP) || !ip.DstIP.Equal(dstIP) {
		t.Fatalf("ip = %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, srcIP, dstIP)
	}
	tcp := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if uint16(tcp.SrcPort) != srcPort || uint16(tcp.DstPort) != dstPort {
		t.Fatalf("tcp = %d -> %d, want %d -> %d", tcp.SrcPort, tcp.DstPort, srcPort, dstPort)
	}
	if !tcp.RST || !tcp.ACK || tcp.SYN || tcp.FIN {
		t.Fatalf("tcp flags RST=%v ACK=%v SYN=%v FIN=%v, want RST+ACK only", tcp.RST, tcp.ACK, tcp.SYN, tcp.FIN)
	}
	if tcp.Seq != seq || tcp.Ack != ack {
		t.Fatalf("tcp seq/ack = %d/%d, want %d/%d", tcp.Seq, tcp.Ack, seq, ack)
	}
}

func assertICMPv4UnreachableFrame(t *testing.T, frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	assertEthernetFrame(t, frame, srcMAC, dstMAC)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip.SrcIP.Equal(srcIP) || !ip.DstIP.Equal(dstIP) {
		t.Fatalf("ip = %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, srcIP, dstIP)
	}
	icmp := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
	if icmp.TypeCode.Type() != layers.ICMPv4TypeDestinationUnreachable || icmp.TypeCode.Code() != layers.ICMPv4CodePort {
		t.Fatalf("icmp type/code = %d/%d, want destination unreachable/port", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	if len(icmp.LayerPayload()) < 28 {
		t.Fatalf("icmp payload len = %d, want quoted IPv4 header and transport prefix", len(icmp.LayerPayload()))
	}
}

func assertICMPv6UnreachableFrame(t *testing.T, frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP) {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	assertEthernetFrame(t, frame, srcMAC, dstMAC)
	ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !ip.SrcIP.Equal(srcIP) || !ip.DstIP.Equal(dstIP) {
		t.Fatalf("ip = %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, srcIP, dstIP)
	}
	icmp := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	if icmp.TypeCode.Type() != layers.ICMPv6TypeDestinationUnreachable || icmp.TypeCode.Code() != layers.ICMPv6CodePortUnreachable {
		t.Fatalf("icmp type/code = %d/%d, want destination unreachable/port", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}
	if len(icmp.LayerPayload()) < 48 {
		t.Fatalf("icmp payload len = %d, want quoted IPv6 header and transport prefix", len(icmp.LayerPayload()))
	}
}

func assertUDPFrame(t *testing.T, frame []byte, srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, rcode int, wantECH bool) {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	assertEthernetFrame(t, frame, srcMAC, dstMAC)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip.SrcIP.Equal(srcIP) || !ip.DstIP.Equal(dstIP) {
		t.Fatalf("ip = %s -> %s, want %s -> %s", ip.SrcIP, ip.DstIP, srcIP, dstIP)
	}
	if int(ip.Length) != len(frame)-14 {
		t.Fatalf("ip length = %d, want %d", ip.Length, len(frame)-14)
	}
	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if uint16(udp.SrcPort) != srcPort || uint16(udp.DstPort) != dstPort {
		t.Fatalf("udp = %d -> %d, want %d -> %d", udp.SrcPort, udp.DstPort, srcPort, dstPort)
	}
	if int(udp.Length) != len(udp.LayerPayload())+8 {
		t.Fatalf("udp length = %d, want %d", udp.Length, len(udp.LayerPayload())+8)
	}
	var msg dns.Msg
	if err := msg.Unpack(udp.LayerPayload()); err != nil {
		t.Fatal(err)
	}
	if msg.Rcode != rcode {
		t.Fatalf("rcode = %d, want %d", msg.Rcode, rcode)
	}
	for _, rr := range msg.Answer {
		https, ok := rr.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, kv := range https.Value {
			if kv.Key() == dns.SVCB_ECHCONFIG && !wantECH {
				t.Fatal("ECH config should have been stripped")
			}
		}
	}
}

func dnsQueryPayload(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dnsrefusal(query []byte) ([]byte, error) {
	var req dns.Msg
	if err := req.Unpack(query); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	resp.SetRcode(&req, dns.RcodeNameError)
	return resp.Pack()
}

func httpsResponsePayload(t *testing.T, ech bool) []byte {
	t.Helper()
	https := &dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBAlpn{Alpn: []string{"h2"}},
		},
	}}
	if ech {
		https.Value = append(https.Value, &dns.SVCBECHConfig{ECH: []byte{0x01, 0x02, 0x03}})
	}
	msg := new(dns.Msg)
	msg.SetReply(new(dns.Msg))
	msg.Answer = []dns.RR{https}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func engineDevice(t *testing.T) Device {
	t.Helper()
	return Device{
		IP:  net.IPv4(192, 168, 1, 50),
		MAC: mustRelayMAC(t, "00:11:22:33:44:55"),
	}
}

func tableWithDevice(ip net.IP, mac net.HardwareAddr) *Table {
	table := NewTable()
	table.Upsert(Device{IP: ip, MAC: mac})
	return table
}

func mustRelayMAC(t *testing.T, s string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
