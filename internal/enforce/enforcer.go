// Package enforce applies per-device traffic policy: hard block, bandwidth throttle, and
// pause/resume. The default backend acts in user space on lemonet's forwarding path, so it
// behaves identically on Linux, macOS, and Windows.
package enforce

import "net/netip"

// Enforcer applies and clears per-device policy. All methods are idempotent and safe for
// concurrent use.
type Enforcer interface {
	// Block drops all traffic to and from ip until Clear.
	Block(ip netip.Addr) error
	// Throttle shapes ip's traffic. up and down are in kbps; 0 means unlimited that direction.
	Throttle(ip netip.Addr, upKbps, downKbps int) error
	// Pause and Resume are quick toggles that drop or restore traffic without losing the
	// device's throttle settings.
	Pause(ip netip.Addr) error
	Resume(ip netip.Addr) error
	// Clear removes all enforcement for ip.
	Clear(ip netip.Addr) error
	// ClearAll removes enforcement for every device, used on shutdown to leave a clean system.
	ClearAll() error
}
