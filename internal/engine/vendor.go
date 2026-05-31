package engine

import "net"

// VendorDB resolves a MAC address to a hardware vendor via its OUI prefix. Discovery works
// without it, so a no-op implementation is a valid default.
type VendorDB interface {
	Lookup(mac net.HardwareAddr) string
}

// NopVendorDB resolves nothing. Used until an OUI database is wired in.
type NopVendorDB struct{}

func (NopVendorDB) Lookup(net.HardwareAddr) string { return "" }
