//go:build darwin

package engine

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

var netstatIPv6RoutesFunc = netstatIPv6Routes

func GatewayIPv6LinkLocal(iface string) (net.IP, error) {
	out, err := netstatIPv6RoutesFunc()
	if err != nil {
		return nil, err
	}
	if gw, ok := parseDarwinIPv6DefaultGateway(out, iface); ok {
		return gw, nil
	}
	return nil, fmt.Errorf("engine: no IPv6 default gateway for %s", iface)
}

func netstatIPv6Routes() ([]byte, error) {
	return exec.Command("netstat", "-rn", "-f", "inet6").Output()
}

func parseDarwinIPv6DefaultGateway(out []byte, iface string) (net.IP, bool) {
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		if len(fields) < 4 || fields[0] != "default" {
			continue
		}
		if !darwinRouteLineHasInterface(fields, iface) {
			continue
		}
		host := strings.Split(fields[1], "%")[0]
		ip := net.ParseIP(host)
		if ip != nil && ip.IsLinkLocalUnicast() {
			return ip, true
		}
	}
	return nil, false
}

func darwinRouteLineHasInterface(fields []string, iface string) bool {
	for _, field := range fields[2:] {
		if field == iface {
			return true
		}
	}
	return false
}
