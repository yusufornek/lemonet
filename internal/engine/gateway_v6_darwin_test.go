//go:build darwin

package engine

import "testing"

func TestGatewayIPv6LinkLocalUsesRouteTable(t *testing.T) {
	old := netstatIPv6RoutesFunc
	t.Cleanup(func() { netstatIPv6RoutesFunc = old })
	netstatIPv6RoutesFunc = func() ([]byte, error) {
		return []byte(`Destination Gateway Flags Netif Expire
default fe80::5e64:8eff:fe64:150%en0 UGcg en0
`), nil
	}

	got, err := GatewayIPv6LinkLocal("en0")
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "fe80::5e64:8eff:fe64:150" {
		t.Fatalf("gateway = %s", got)
	}
}

func TestParseDarwinIPv6DefaultGateway(t *testing.T) {
	out := []byte(`Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::5e64:8eff:fe64:150%en0            UGcg                  en0
default                                 fe80::%utun0                            UGcIg               utun0
::1                                     ::1                                     UHL                   lo0
`)

	got, ok := parseDarwinIPv6DefaultGateway(out, "en0")
	if !ok {
		t.Fatal("default IPv6 gateway for en0 was not parsed")
	}
	if got.String() != "fe80::5e64:8eff:fe64:150" {
		t.Fatalf("gateway = %s", got)
	}
}

func TestParseDarwinIPv6DefaultGatewayRejectsWrongInterface(t *testing.T) {
	out := []byte(`Destination Gateway Flags Netif Expire
default fe80::5e64:8eff:fe64:150%en0 UGcg en0
`)

	if got, ok := parseDarwinIPv6DefaultGateway(out, "en1"); ok {
		t.Fatalf("gateway for wrong interface = %s", got)
	}
}
