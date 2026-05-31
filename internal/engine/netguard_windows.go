//go:build windows

package engine

// Windows does not emit IPv4 ICMP redirects in a way that defeats the relay, so the guard is a
// no-op. The relay carries traffic in user space regardless.
type noopGuard struct{}

func NewSessionGuard() SessionGuard { return noopGuard{} }

func (noopGuard) Begin() error { return nil }

func (noopGuard) End() error { return nil }
