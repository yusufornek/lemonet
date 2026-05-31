package engine

import (
	"bufio"
	"embed"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// VendorDB resolves a MAC address to a hardware vendor via its OUI prefix. Discovery works
// without it, so a no-op implementation is a valid default.
type VendorDB interface {
	Lookup(mac net.HardwareAddr) string
}

// NopVendorDB resolves nothing.
type NopVendorDB struct{}

func (NopVendorDB) Lookup(net.HardwareAddr) string { return "" }

//go:embed data/oui.csv
var ouiSeed embed.FS

// OUIVendorDB maps a MAC's 24-bit OUI prefix to a vendor name. It loads a small built-in seed and,
// if present, a fuller "oui.csv" the user dropped into the config directory.
type OUIVendorDB struct {
	prefixes map[string]string
}

// LoadVendorDB builds the vendor database from the embedded seed plus an optional user-provided
// file. It never fails: an unreadable source just yields fewer entries.
func LoadVendorDB() *OUIVendorDB {
	db := &OUIVendorDB{prefixes: make(map[string]string)}
	if f, err := ouiSeed.Open("data/oui.csv"); err == nil {
		db.load(f)
		_ = f.Close()
	}
	if dir, err := os.UserConfigDir(); err == nil {
		if f, err := os.Open(filepath.Join(dir, "lemonet", "oui.csv")); err == nil {
			db.load(f)
			_ = f.Close()
		}
	}
	return db
}

func (db *OUIVendorDB) load(r io.Reader) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		prefix := normalizePrefix(parts[0])
		if len(prefix) == 6 {
			db.prefixes[prefix] = strings.TrimSpace(parts[1])
		}
	}
}

func (db *OUIVendorDB) Lookup(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	return db.prefixes[normalizePrefix(mac.String()[:8])]
}

// normalizePrefix reduces a MAC or OUI string to its first 6 lowercase hex digits, dropping any
// ":", "-", or "." separators.
func normalizePrefix(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(":", "", "-", "", ".", "").Replace(s)
	if len(s) > 6 {
		s = s[:6]
	}
	return s
}
