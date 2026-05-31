//go:build linux

package engine

import (
	"os"
	"strings"
)

const linuxSendRedirects = "/proc/sys/net/ipv4/conf/all/send_redirects"

type linuxGuard struct {
	prev    bool
	applied bool
}

func NewSessionGuard() SessionGuard { return &linuxGuard{} }

func (g *linuxGuard) Begin() error {
	g.prev, _ = readProcBool(linuxSendRedirects)
	g.applied = true
	return writeProcBool(linuxSendRedirects, false)
}

func (g *linuxGuard) End() error {
	if !g.applied {
		return nil
	}
	g.applied = false
	return writeProcBool(linuxSendRedirects, g.prev)
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
