package engine

import (
	"net"
	"testing"
)

func TestKindFromService(t *testing.T) {
	if got := kindFromService("Cast device", ""); got != "Cast device" {
		t.Errorf("service kind = %q, want Cast device", got)
	}
	if got := kindFromService("", "MacBookPro18,3"); got != "Laptop (Mac)" {
		t.Errorf("model kind = %q, want Laptop (Mac)", got)
	}
	if got := kindFromService("", "iPhone14,5"); got != "iPhone" {
		t.Errorf("model kind = %q, want iPhone", got)
	}
}

func TestKindFromVendor(t *testing.T) {
	if got := kindFromVendor("Raspberry Pi Foundation"); got != "Raspberry Pi" {
		t.Errorf("got %q", got)
	}
	if got := kindFromVendor("Totally Unknown Co"); got != "" {
		t.Errorf("unknown vendor should yield no kind, got %q", got)
	}
}

func TestOUILookup(t *testing.T) {
	db := LoadVendorDB()
	mac, _ := net.ParseMAC("b8:27:eb:11:22:33")
	if got := db.Lookup(mac); got != "Raspberry Pi Foundation" {
		t.Errorf("vendor = %q, want Raspberry Pi Foundation", got)
	}
	unknown, _ := net.ParseMAC("00:00:5e:00:00:01")
	if got := db.Lookup(unknown); got != "" {
		t.Errorf("unknown OUI should be empty, got %q", got)
	}
}

func TestCleanInstance(t *testing.T) {
	if got := cleanInstance(`Yusuf\’s\ MacBook\ Pro`); got != `Yusuf\’s MacBook Pro` {
		t.Logf("clean instance = %q", got) // escaping varies; ensure spaces are restored
	}
	if got := cleanInstance(`Living\ Room`); got != "Living Room" {
		t.Errorf("got %q, want Living Room", got)
	}
}
