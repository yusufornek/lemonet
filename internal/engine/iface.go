package engine

import (
	"errors"
	"fmt"
	"net"

	"github.com/jackpal/gateway"
)

// Interface is a usable network interface with the local IPv4 details lemonet needs to scan
// and to craft frames from.
type Interface struct {
	Name      string
	MAC       net.HardwareAddr
	IP        net.IP
	Subnet    *net.IPNet
	LinkLocal net.IP // fe80:: address used as the source for NDP, if the interface has one
}

// ListInterfaces returns interfaces that are up, not loopback, and have an IPv4 address.
func ListInterfaces() ([]Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		ip, subnet := firstIPv4(ifi)
		if ip == nil {
			continue
		}
		out = append(out, Interface{Name: ifi.Name, MAC: ifi.HardwareAddr, IP: ip, Subnet: subnet, LinkLocal: firstLinkLocal(ifi)})
	}
	return out, nil
}

// LookupInterface resolves a single interface by name into the form the engine needs.
func LookupInterface(name string) (Interface, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return Interface{}, err
	}
	ip, subnet := firstIPv4(*ifi)
	if ip == nil {
		return Interface{}, fmt.Errorf("engine: interface %q has no IPv4 address", name)
	}
	return Interface{Name: ifi.Name, MAC: ifi.HardwareAddr, IP: ip, Subnet: subnet, LinkLocal: firstLinkLocal(*ifi)}, nil
}

// firstLinkLocal returns the interface's IPv6 link-local (fe80::/10) address, or nil.
func firstLinkLocal(ifi net.Interface) net.IP {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := ipnet.IP.To16(); ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return ip
		}
	}
	return nil
}

func firstIPv4(ifi net.Interface) (net.IP, *net.IPNet) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipnet.IP.To4(); v4 != nil {
			return v4, &net.IPNet{IP: v4, Mask: ipnet.Mask}
		}
	}
	return nil, nil
}

// GatewayIP returns the IPv4 default gateway for the host.
func GatewayIP() (net.IP, error) {
	gw, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, err
	}
	v4 := gw.To4()
	if v4 == nil {
		return nil, errors.New("engine: default gateway is not IPv4")
	}
	return v4, nil
}
