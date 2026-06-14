package filter

import "net/netip"

const (
	portDoH         = 443
	portDoQAlt      = 784
	portDNSCrypt    = 5353
	portDNSCryptAlt = 5443
	portDoT         = 853
	portDoHAlt      = 8443
	portDoQAlt2     = 8853
)

var encryptedDNSResolverIPs = map[netip.Addr]struct{}{
	netip.MustParseAddr("1.1.1.1"):              {},
	netip.MustParseAddr("1.0.0.1"):              {},
	netip.MustParseAddr("2606:4700:4700::1111"): {},
	netip.MustParseAddr("2606:4700:4700::1001"): {},
	netip.MustParseAddr("1.1.1.2"):              {},
	netip.MustParseAddr("1.0.0.2"):              {},
	netip.MustParseAddr("2606:4700:4700::1112"): {},
	netip.MustParseAddr("2606:4700:4700::1002"): {},
	netip.MustParseAddr("1.1.1.3"):              {},
	netip.MustParseAddr("1.0.0.3"):              {},
	netip.MustParseAddr("2606:4700:4700::1113"): {},
	netip.MustParseAddr("2606:4700:4700::1003"): {},
	netip.MustParseAddr("8.8.8.8"):              {},
	netip.MustParseAddr("8.8.4.4"):              {},
	netip.MustParseAddr("2001:4860:4860::8888"): {},
	netip.MustParseAddr("2001:4860:4860::8844"): {},
	netip.MustParseAddr("9.9.9.9"):              {},
	netip.MustParseAddr("9.9.9.10"):             {},
	netip.MustParseAddr("9.9.9.11"):             {},
	netip.MustParseAddr("149.112.112.9"):        {},
	netip.MustParseAddr("149.112.112.10"):       {},
	netip.MustParseAddr("149.112.112.11"):       {},
	netip.MustParseAddr("149.112.112.112"):      {},
	netip.MustParseAddr("2620:fe::fe"):          {},
	netip.MustParseAddr("2620:fe::9"):           {},
	netip.MustParseAddr("2620:fe::10"):          {},
	netip.MustParseAddr("2620:fe::11"):          {},
	netip.MustParseAddr("2620:fe::fe:9"):        {},
	netip.MustParseAddr("2620:fe::fe:10"):       {},
	netip.MustParseAddr("2620:fe::fe:11"):       {},
	netip.MustParseAddr("208.67.222.222"):       {},
	netip.MustParseAddr("208.67.220.220"):       {},
	netip.MustParseAddr("146.112.41.2"):         {},
	netip.MustParseAddr("146.112.41.3"):         {},
	netip.MustParseAddr("2620:119:35::35"):      {},
	netip.MustParseAddr("2620:119:53::53"):      {},
	netip.MustParseAddr("2620:119:fc::2"):       {},
	netip.MustParseAddr("2620:119:fc::3"):       {},
	netip.MustParseAddr("104.16.248.249"):       {},
	netip.MustParseAddr("104.16.249.249"):       {},
	netip.MustParseAddr("2606:4700::6810:f8f9"): {},
	netip.MustParseAddr("2606:4700::6810:f9f9"): {},
	netip.MustParseAddr("162.159.61.4"):         {},
	netip.MustParseAddr("172.64.41.4"):          {},
	netip.MustParseAddr("2803:f800:53::4"):      {},
	netip.MustParseAddr("2a06:98c1:52::4"):      {},
	netip.MustParseAddr("45.90.28.0"):           {},
	netip.MustParseAddr("45.90.30.0"):           {},
	netip.MustParseAddr("2a07:a8c0::"):          {},
	netip.MustParseAddr("2a07:a8c1::"):          {},
	netip.MustParseAddr("94.140.14.14"):         {},
	netip.MustParseAddr("94.140.15.15"):         {},
	netip.MustParseAddr("94.140.14.15"):         {},
	netip.MustParseAddr("94.140.15.16"):         {},
	netip.MustParseAddr("94.140.14.140"):        {},
	netip.MustParseAddr("94.140.14.141"):        {},
	netip.MustParseAddr("2a10:50c0::1:ff"):      {},
	netip.MustParseAddr("2a10:50c0::2:ff"):      {},
	netip.MustParseAddr("2a10:50c0::ad1:ff"):    {},
	netip.MustParseAddr("2a10:50c0::ad2:ff"):    {},
	netip.MustParseAddr("185.228.168.10"):       {},
	netip.MustParseAddr("185.228.168.168"):      {},
	netip.MustParseAddr("185.228.168.9"):        {},
	netip.MustParseAddr("185.228.169.9"):        {},
	netip.MustParseAddr("2a0d:2a00:1::2"):       {},
	netip.MustParseAddr("2a0d:2a00:2::2"):       {},
	netip.MustParseAddr("76.76.2.0"):            {},
	netip.MustParseAddr("76.76.10.0"):           {},
	netip.MustParseAddr("2606:1a40::"):          {},
	netip.MustParseAddr("2606:1a40:1::"):        {},
	netip.MustParseAddr("194.242.2.2"):          {},
	netip.MustParseAddr("194.242.2.4"):          {},
	netip.MustParseAddr("194.242.2.5"):          {},
	netip.MustParseAddr("194.242.2.6"):          {},
	netip.MustParseAddr("194.242.2.9"):          {},
	netip.MustParseAddr("2a07:e340::2"):         {},
	netip.MustParseAddr("2a07:e340::4"):         {},
	netip.MustParseAddr("2a07:e340::5"):         {},
	netip.MustParseAddr("2a07:e340::6"):         {},
	netip.MustParseAddr("2a07:e340::9"):         {},
}

var encryptedDNSResolverPrefixes = []netip.Prefix{
	netip.MustParsePrefix("45.90.28.0/24"),
	netip.MustParsePrefix("45.90.30.0/24"),
	netip.MustParsePrefix("76.76.2.0/24"),
	netip.MustParsePrefix("76.76.10.0/24"),
	netip.MustParsePrefix("2a07:a8c0::/48"),
	netip.MustParsePrefix("2a07:a8c1::/48"),
	netip.MustParsePrefix("2606:1a40::/48"),
	netip.MustParsePrefix("2606:1a40:1::/48"),
}

func knownEncryptedDNSResolver(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	normalized := addr.Unmap()
	if _, ok := encryptedDNSResolverIPs[normalized]; ok {
		return true
	}
	for _, prefix := range encryptedDNSResolverPrefixes {
		if prefix.Contains(normalized) {
			return true
		}
	}
	return false
}

func encryptedDNSServicePort(port uint16) bool {
	switch port {
	case portDoH, portDoQAlt, portDNSCrypt, portDNSCryptAlt, portDoT, portDoHAlt, portDoQAlt2:
		return true
	default:
		return false
	}
}
