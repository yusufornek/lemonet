package engine

// Forwarding toggles the host's IP forwarding so intercepted traffic reaches the real gateway
// instead of being dropped. Enable returns the prior state so Restore can put it back exactly,
// never clobbering a value the user set themselves.
type Forwarding interface {
	Enable() (prev bool, err error)
	Restore(prev bool) error
}
