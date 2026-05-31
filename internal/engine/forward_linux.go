//go:build linux

package engine

import (
	"os"
	"strings"
)

const linuxForwardPath = "/proc/sys/net/ipv4/ip_forward"

type procForwarding struct{}

func NewForwarding() Forwarding { return procForwarding{} }

func (procForwarding) Enable() (bool, error) {
	prev, err := readProcBool(linuxForwardPath)
	if err != nil {
		return false, err
	}
	if prev {
		return true, nil
	}
	return false, writeProcBool(linuxForwardPath, true)
}

func (procForwarding) Restore(prev bool) error {
	if prev {
		return nil
	}
	return writeProcBool(linuxForwardPath, false)
}

func readProcBool(path string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(b)) == "1", nil
}

func writeProcBool(path string, v bool) error {
	val := "0"
	if v {
		val = "1"
	}
	return os.WriteFile(path, []byte(val), 0o644)
}
