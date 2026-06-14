package sni

import (
	"crypto/tls"
	"encoding/binary"
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

func TestClientHelloDetection(t *testing.T) {
	hello := captureClientHello(t, "")
	if !IsClientHello(hello) {
		t.Fatal("TLS ClientHello without SNI should still be recognized")
	}
	if _, ok := Parse(hello); ok {
		t.Fatal("TLS ClientHello without SNI should not parse a host")
	}
	if IsClientHello([]byte{0x17, 0x03, 0x03, 0x00, 0x20}) {
		t.Fatal("TLS application data is not a ClientHello")
	}
}

func TestIncompleteClientHelloDetection(t *testing.T) {
	hello := captureClientHello(t, "panel.example.com")
	if !IsIncompleteClientHello(hello[:11]) {
		t.Fatal("split TLS ClientHello prefix should be recognized as incomplete")
	}
	if IsIncompleteClientHello(hello) {
		t.Fatal("complete TLS ClientHello should not be reported as incomplete")
	}
	if IsIncompleteClientHello([]byte{0x17, 0x03, 0x03, 0x00, 0x20}) {
		t.Fatal("TLS application data is not an incomplete ClientHello")
	}
}

func TestHasECHDetectsEncryptedClientHelloExtension(t *testing.T) {
	hello := captureClientHello(t, "cover.example.com")
	if HasECH(hello) {
		t.Fatal("ordinary TLS ClientHello should not report ECH")
	}

	hello = clientHelloWithExtension(t, hello, 0xfe0d, []byte{0x01, 0x02})
	if !HasECH(hello) {
		t.Fatal("TLS ClientHello with encrypted_client_hello extension should report ECH")
	}

	host, ok := Parse(hello)
	if !ok || host != "cover.example.com" {
		t.Fatalf("host = %q/%v, want cover.example.com/true", host, ok)
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

func clientHelloWithExtension(t *testing.T, hello []byte, extType uint16, extData []byte) []byte {
	t.Helper()
	out := append([]byte(nil), hello...)
	if len(out) < 9 || out[0] != recordHandshake || out[5] != handshakeClient {
		t.Fatalf("input is not a TLS ClientHello record")
	}

	recordLen := int(binary.BigEndian.Uint16(out[3:5]))
	handshakeLen := int(out[6])<<16 | int(out[7])<<8 | int(out[8])
	if len(out) != 5+recordLen || recordLen != 4+handshakeLen {
		t.Fatalf("unexpected ClientHello record shape")
	}

	pos := 9
	pos += 2 + 32
	if pos >= len(out) {
		t.Fatalf("truncated ClientHello before session id")
	}
	sessionLen := int(out[pos])
	pos += 1 + sessionLen
	if pos+2 > len(out) {
		t.Fatalf("truncated ClientHello before cipher suites")
	}
	cipherLen := int(binary.BigEndian.Uint16(out[pos : pos+2]))
	pos += 2 + cipherLen
	if pos >= len(out) {
		t.Fatalf("truncated ClientHello before compression methods")
	}
	compressionLen := int(out[pos])
	pos += 1 + compressionLen
	if pos+2 > len(out) {
		t.Fatalf("truncated ClientHello before extensions")
	}

	extLenPos := pos
	extLen := int(binary.BigEndian.Uint16(out[extLenPos : extLenPos+2]))
	if extLenPos+2+extLen != len(out) {
		t.Fatalf("unexpected ClientHello extension block length")
	}

	extension := make([]byte, 4+len(extData))
	binary.BigEndian.PutUint16(extension[:2], extType)
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(extData)))
	copy(extension[4:], extData)

	recordLen += len(extension)
	handshakeLen += len(extension)
	extLen += len(extension)
	if recordLen > 0xffff || handshakeLen > 0xffffff || extLen > 0xffff {
		t.Fatalf("ClientHello extension would exceed TLS length fields")
	}

	out = append(out, extension...)
	binary.BigEndian.PutUint16(out[3:5], uint16(recordLen))
	out[6] = byte(handshakeLen >> 16)
	out[7] = byte(handshakeLen >> 8)
	out[8] = byte(handshakeLen)
	binary.BigEndian.PutUint16(out[extLenPos:extLenPos+2], uint16(extLen))
	return out
}
