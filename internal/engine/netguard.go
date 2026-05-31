package engine

// SessionGuard adjusts host network settings that would otherwise let a poisoned device route
// around the relay. The main culprit is ICMP redirects: while a session is active the host must
// not advertise a better route back to the real gateway. Begin snapshots and applies the change;
// End restores the exact prior state.
type SessionGuard interface {
	Begin() error
	End() error
}
