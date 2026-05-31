package engine

import (
	"context"
	"strings"
	"sync"

	"github.com/grandcat/zeroconf"
)

// mdnsServices are the Bonjour/DNS-SD service types lemonet browses to learn device names and
// roles. The kind is a coarse human label; an empty kind means the service only contributes a
// name (and possibly a model from its TXT records).
var mdnsServices = []struct {
	service string
	kind    string
}{
	{"_companion-link._tcp", "Apple device"},
	{"_airplay._tcp", "Apple TV / AirPlay"},
	{"_raop._tcp", "AirPlay speaker"},
	{"_googlecast._tcp", "Cast device"},
	{"_spotify-connect._tcp", "Speaker"},
	{"_printer._tcp", "Printer"},
	{"_ipp._tcp", "Printer"},
	{"_smb._tcp", "Computer"},
	{"_ssh._tcp", "Computer"},
	{"_homekit._tcp", "Smart home"},
	{"_device-info._tcp", ""},
}

// enrichMDNS browses the mDNS service types until ctx is done and merges any device names and
// roles into the table by IP. Discovery does not depend on this; failures are silent.
func (s *Scanner) enrichMDNS(ctx context.Context, table *Table) {
	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	for _, svc := range mdnsServices {
		entries := make(chan *zeroconf.ServiceEntry, 16)
		wg.Add(1)
		go func(kind string) {
			defer wg.Done()
			for e := range entries {
				name := cleanInstance(e.Instance)
				model := txtValue(e.Text, "model")
				for _, ip := range e.AddrIPv4 {
					table.MergeByIP(ip, name, kindFromService(kind, model), "")
				}
			}
		}(svc.kind)

		// zeroconf closes entries when ctx is done, which ends the consumer above.
		go func(service string, out chan *zeroconf.ServiceEntry) {
			_ = resolver.Browse(ctx, service, "local.", out)
		}(svc.service, entries)
	}

	<-ctx.Done()
	wg.Wait()
}

// cleanInstance turns an mDNS instance label into a readable device name, undoing the DNS-SD
// escaping of spaces ("\ ") and apostrophes.
func cleanInstance(instance string) string {
	r := strings.NewReplacer(`\ `, " ", `\.`, ".", `\\`, `\`)
	return strings.TrimSpace(r.Replace(instance))
}

func txtValue(text []string, key string) string {
	prefix := key + "="
	for _, t := range text {
		if strings.HasPrefix(t, prefix) {
			return strings.TrimPrefix(t, prefix)
		}
	}
	return ""
}
