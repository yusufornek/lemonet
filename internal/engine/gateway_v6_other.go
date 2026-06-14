//go:build !darwin

package engine

import (
	"fmt"
	"net"
)

func GatewayIPv6LinkLocal(iface string) (net.IP, error) {
	return nil, fmt.Errorf("engine: IPv6 gateway route fallback is not available for %s", iface)
}
