//go:build darwin

package engine

import (
	"os/exec"
	"strings"
)

const darwinForwardKey = "net.inet.ip.forwarding"

type sysctlForwarding struct{}

func NewForwarding() Forwarding { return sysctlForwarding{} }

func (sysctlForwarding) Enable() (bool, error) {
	prev, err := readSysctlBool(darwinForwardKey)
	if err != nil {
		return false, err
	}
	if prev {
		return true, nil
	}
	return false, writeSysctlBool(darwinForwardKey, true)
}

func (sysctlForwarding) Restore(prev bool) error {
	if prev {
		return nil
	}
	return writeSysctlBool(darwinForwardKey, false)
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
