//go:build darwin

package engine

import (
	"os/exec"
	"strings"
)

const (
	darwinRedirectV4 = "net.inet.ip.redirect"
	darwinRedirectV6 = "net.inet6.ip6.redirect"
)

type darwinGuard struct {
	prevV4, prevV6 bool
	applied        bool
}

func NewSessionGuard() SessionGuard { return &darwinGuard{} }

func (g *darwinGuard) Begin() error {
	g.prevV4, _ = readSysctlBool(darwinRedirectV4)
	g.prevV6, _ = readSysctlBool(darwinRedirectV6)
	g.applied = true
	if err := writeSysctlBool(darwinRedirectV4, false); err != nil {
		return err
	}
	_ = writeSysctlBool(darwinRedirectV6, false) // best-effort
	return nil
}

func (g *darwinGuard) End() error {
	if !g.applied {
		return nil
	}
	g.applied = false
	_ = writeSysctlBool(darwinRedirectV4, g.prevV4)
	_ = writeSysctlBool(darwinRedirectV6, g.prevV6)
	return nil
}

func readSysctlBool(key string) (bool, error) {
	out, err := exec.Command("sysctl", "-n", key).Output()
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "1", nil
}

func writeSysctlBool(key string, v bool) error {
	val := "0"
	if v {
		val = "1"
	}
	return exec.Command("sysctl", "-w", key+"="+val).Run()
}
