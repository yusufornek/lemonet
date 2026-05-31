//go:build windows

package engine

// On Windows, enabling the kernel IP router (IPEnableRouter) requires a reboot, so lemonet
// forwards intercepted packets in user space instead. This no-op satisfies the interface; the
// userspace forwarder on the capture path does the real work.
type noopForwarding struct{}

func NewForwarding() Forwarding { return noopForwarding{} }

func (noopForwarding) Enable() (bool, error) { return false, nil }

func (noopForwarding) Restore(bool) error { return nil }
