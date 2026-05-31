// Package sni extracts the Server Name Indication from a TLS ClientHello without decrypting the
// connection. SNI is sent in plaintext in TLS 1.3 for the vast majority of sites, which lets
// lemonet block by domain without a man-in-the-middle certificate.
package sni

import "encoding/binary"

const (
	recordHandshake  = 0x16
	handshakeClient  = 0x01
	extServerName    = 0x0000
	nameTypeHostName = 0x00
)

// Parse reads a TLS record carrying a ClientHello and returns the SNI host name. ok is false if
// the bytes are not a ClientHello or carry no server_name extension (for example, an ECH-wrapped
// ClientHello, where the real name is encrypted).
func Parse(record []byte) (host string, ok bool) {
	r := reader{b: record}
	if r.u8() != recordHandshake {
		return "", false
	}
	r.skip(2)         // record version
	recLen := r.u16() // record length
	body := r.take(int(recLen))
	if r.err {
		return "", false
	}

	h := reader{b: body}
	if h.u8() != handshakeClient {
		return "", false
	}
	h.skip(3)            // handshake length
	h.skip(2)            // client version
	h.skip(32)           // random
	h.take(int(h.u8()))  // session id
	h.take(int(h.u16())) // cipher suites
	h.take(int(h.u8()))  // compression methods

	extTotal := h.u16()
	exts := h.take(int(extTotal))
	if h.err {
		return "", false
	}

	e := reader{b: exts}
	for !e.err && e.remaining() >= 4 {
		extType := e.u16()
		extData := e.take(int(e.u16()))
		if extType == extServerName {
			return parseServerName(extData)
		}
	}
	return "", false
}

func parseServerName(data []byte) (string, bool) {
	s := reader{b: data}
	s.skip(2) // server_name_list length
	if s.u8() != nameTypeHostName {
		return "", false
	}
	name := s.take(int(s.u16()))
	if s.err || len(name) == 0 {
		return "", false
	}
	return string(name), true
}

// reader is a bounds-checked sequential byte reader; any out-of-range read sets err and makes
// subsequent reads return zero so callers can check err once at the end.
type reader struct {
	b   []byte
	pos int
	err bool
}

func (r *reader) remaining() int { return len(r.b) - r.pos }

func (r *reader) u8() byte {
	if r.pos+1 > len(r.b) {
		r.err = true
		return 0
	}
	v := r.b[r.pos]
	r.pos++
	return v
}

func (r *reader) u16() uint16 {
	if r.pos+2 > len(r.b) {
		r.err = true
		return 0
	}
	v := binary.BigEndian.Uint16(r.b[r.pos:])
	r.pos += 2
	return v
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) take(n int) []byte {
	if n < 0 || r.pos+n > len(r.b) {
		r.err = true
		return nil
	}
	v := r.b[r.pos : r.pos+n]
	r.pos += n
	return v
}
