//go:build darwin

package engine

import (
	"errors"
	"fmt"
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

var (
	readSysctlBoolFunc  = readSysctlBool
	writeSysctlBoolFunc = writeSysctlBool
)

func NewSessionGuard() SessionGuard { return &darwinGuard{} }

func (g *darwinGuard) Begin() error {
	prevV4, err := readSysctlBoolFunc(darwinRedirectV4)
	if err != nil {
		return fmt.Errorf("engine: read %s: %w", darwinRedirectV4, err)
	}
	prevV6, err := readSysctlBoolFunc(darwinRedirectV6)
	if err != nil {
		return fmt.Errorf("engine: read %s: %w", darwinRedirectV6, err)
	}
	if err := writeSysctlBoolFunc(darwinRedirectV4, false); err != nil {
		return err
	}
	g.prevV4, g.prevV6 = prevV4, prevV6
	g.applied = true
	_ = writeSysctlBoolFunc(darwinRedirectV6, false) // best-effort
	return nil
}

func (g *darwinGuard) End() error {
	if !g.applied {
		return nil
	}
	g.applied = false
	return errors.Join(
		writeSysctlBoolFunc(darwinRedirectV4, g.prevV4),
		writeSysctlBoolFunc(darwinRedirectV6, g.prevV6),
	)
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
	var arg string
	switch key {
	case darwinRedirectV4:
		arg = darwinRedirectV4 + "=" + val
	case darwinRedirectV6:
		arg = darwinRedirectV6 + "=" + val
	default:
		return fmt.Errorf("engine: unsupported sysctl key %s", key)
	}
	// #nosec G204 -- arg is built from the fixed sysctl allowlist above.
	return exec.Command("sysctl", "-w", arg).Run()
}
