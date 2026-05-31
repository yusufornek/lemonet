// Package engine implements lemonet's LAN control core: device discovery, ARP-based
// man-in-the-middle, packet forwarding, and restoration of the network to its prior state.
package engine

import (
	"net"
	"sync"
	"time"
)

// Device is a host observed on the LAN, identified by its MAC. Fields other than MAC are
// best-effort and filled from whatever discovery signal resolved them.
type Device struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Vendor   string
	Hostname string
	Kind     string
	LastSeen time.Time
}

// Table is a concurrent set of discovered devices keyed by MAC address. Discovery signals
// (ARP, mDNS, OUI, rDNS) merge into the same record rather than producing duplicates.
type Table struct {
	mu      sync.RWMutex
	devices map[string]*Device
	v6ByMAC map[string][]net.IP // device MAC -> learned global IPv6 addresses
	v6Owner map[string]string   // IPv6 string -> device MAC
}

func NewTable() *Table {
	return &Table{
		devices: make(map[string]*Device),
		v6ByMAC: make(map[string][]net.IP),
		v6Owner: make(map[string]string),
	}
}

// RecordV6 associates a global IPv6 address with a device (by MAC), learned by observing the
// device's traffic. It lets the relay route IPv6 download traffic and the spoofer poison the
// gateway for that address. Non-global addresses are ignored.
func (t *Table) RecordV6(mac net.HardwareAddr, ip net.IP) {
	v6 := ip.To16()
	if v6 == nil || v6.To4() != nil || !v6.IsGlobalUnicast() {
		return
	}
	key := mac.String()
	id := v6.String()
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, seen := t.v6Owner[id]; seen {
		return
	}
	t.v6Owner[id] = key
	t.v6ByMAC[key] = append(t.v6ByMAC[key], append(net.IP(nil), v6...))
}

// DeviceByV6 returns the device that owns an IPv6 address.
func (t *Table) DeviceByV6(ip net.IP) (Device, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	mac, ok := t.v6Owner[ip.String()]
	if !ok {
		return Device{}, false
	}
	d, ok := t.devices[mac]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// V6Addrs returns the global IPv6 addresses learned for a device.
func (t *Table) V6Addrs(mac net.HardwareAddr) []net.IP {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]net.IP(nil), t.v6ByMAC[mac.String()]...)
}

// Upsert merges d into the table. Non-empty fields on d overwrite existing values; empty
// fields are preserved so a later, richer signal does not erase an earlier one.
func (t *Table) Upsert(d Device) {
	key := d.MAC.String()
	t.mu.Lock()
	defer t.mu.Unlock()

	cur, ok := t.devices[key]
	if !ok {
		cp := d
		t.devices[key] = &cp
		return
	}
	if d.IP != nil {
		cur.IP = d.IP
	}
	if d.Vendor != "" {
		cur.Vendor = d.Vendor
	}
	if d.Hostname != "" {
		cur.Hostname = d.Hostname
	}
	if d.Kind != "" {
		cur.Kind = d.Kind
	}
	if !d.LastSeen.IsZero() {
		cur.LastSeen = d.LastSeen
	}
}

func (t *Table) List() []Device {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]Device, 0, len(t.devices))
	for _, d := range t.devices {
		out = append(out, *d)
	}
	return out
}

func (t *Table) Get(mac net.HardwareAddr) (Device, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	d, ok := t.devices[mac.String()]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// MergeByIP enriches an already-discovered device (matched by IP) with name, kind, or vendor
// learned from a signal that does not carry a MAC, such as mDNS or reverse DNS. Empty fields are
// ignored, and kind/vendor only fill when not already set so a stronger signal is not overwritten.
func (t *Table) MergeByIP(ip net.IP, hostname, kind, vendor string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, d := range t.devices {
		if !d.IP.Equal(ip) {
			continue
		}
		if hostname != "" {
			d.Hostname = hostname
		}
		if kind != "" && d.Kind == "" {
			d.Kind = kind
		}
		if vendor != "" && d.Vendor == "" {
			d.Vendor = vendor
		}
		return
	}
}

func (t *Table) GetByIP(ip net.IP) (Device, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, d := range t.devices {
		if d.IP.Equal(ip) {
			return *d, true
		}
	}
	return Device{}, false
}
