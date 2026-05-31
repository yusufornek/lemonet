package sni

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// captureClientHello drives a real TLS handshake over an in-memory pipe and returns the first
// record the client writes, which is the ClientHello.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()

	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("reading ClientHello: %v", err)
	}
	return buf[:n]
}

func TestParseSNI(t *testing.T) {
	hello := captureClientHello(t, "panel.example.com")
	host, ok := Parse(hello)
	if !ok {
		t.Fatal("expected to parse SNI")
	}
	if host != "panel.example.com" {
		t.Errorf("host = %q, want panel.example.com", host)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, ok := Parse([]byte{0x16, 0x03, 0x01, 0x00}); ok {
		t.Error("truncated record should not parse")
	}
	if _, ok := Parse(nil); ok {
		t.Error("nil should not parse")
	}
}
