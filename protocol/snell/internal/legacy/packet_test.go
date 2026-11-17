package legacy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

type memoryConn struct {
	input  io.Reader
	output bytes.Buffer
	closed bool
}

func (c *memoryConn) Read(p []byte) (int, error)       { return c.input.Read(p) }
func (c *memoryConn) Write(p []byte) (int, error)      { return c.output.Write(p) }
func (c *memoryConn) Close() error                     { c.closed = true; return nil }
func (c *memoryConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *memoryConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *memoryConn) SetDeadline(time.Time) error      { return nil }
func (c *memoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

func packetClient(t *testing.T, raw *memoryConn) (*Client, *packetConn) {
	t.Helper()
	c, err := NewClient(ClientOptions{Version: 3, PSK: testPSK})
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.newSession(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, &packetConn{session: s}
}

func TestUDPRequestAddressVectors(t *testing.T) {
	cases := []struct{ target, header string }{
		{"192.0.2.1:53", "010004c00002010035"},
		{"[2001:db8::1]:5353", "01000620010db800000000000000000000000114e9"},
		{"example.com:53", "010b6578616d706c652e636f6d0035"},
		{"[::ffff:192.0.2.1]:53", "010004c00002010035"},
	}
	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			raw := &memoryConn{input: bytes.NewReader(nil)}
			_, pc := packetClient(t, raw)
			if err := pc.WritePacket(buf.As([]byte("dns")), M.ParseSocksaddr(tc.target)); err != nil {
				t.Fatal(err)
			}
			r := recordReader{upstream: &raw.output, psk: testPSK}
			p, err := r.readRecord()
			if err != nil || !bytes.Equal(p, []byte{1, 6, 0}) {
				t.Fatalf("UDP handshake %x %v", p, err)
			}
			p, err = r.readRecord()
			if err != nil {
				t.Fatal(err)
			}
			expected, _ := hex.DecodeString(tc.header)
			expected = append(expected, []byte("dns")...)
			if !bytes.Equal(p, expected) {
				t.Fatalf("frame %x, want %x", p, expected)
			}
		})
	}
}

func TestUDPDatagramLimits(t *testing.T) {
	for _, host := range []string{"192.0.2.1", "2001:db8::1", "example.com", strings.Repeat("a", 255)} {
		t.Run(host, func(t *testing.T) {
			raw := &memoryConn{input: bytes.NewReader(nil)}
			_, pc := packetClient(t, raw)
			dest := M.ParseSocksaddrHostPort(host, 53)
			h := buf.NewSize(300)
			h.WriteByte(1)
			if err := snell.WriteUDPRequestAddress(h, dest); err != nil {
				t.Fatal(err)
			}
			size := maxPayload - h.Len()
			h.Release()
			if err := pc.WritePacket(buf.As(make([]byte, size+1)), dest); !errors.Is(err, snell.ErrPayloadTooLarge) {
				t.Fatal(err)
			}
			if raw.output.Len() != 0 {
				t.Fatal("oversized datagram wrote handshake or partial frame")
			}
			if err := pc.WritePacket(buf.As(make([]byte, size)), dest); err != nil {
				t.Fatal(err)
			}
			if err := pc.WritePacket(buf.As(nil), dest); err != nil {
				t.Fatal(err)
			}
			r := recordReader{upstream: &raw.output, psk: testPSK}
			r.readRecord()
			p, err := r.readRecord()
			if err != nil || len(p) != maxPayload {
				t.Fatalf("boundary record: %d %v", len(p), err)
			}
			p, err = r.readRecord()
			if err != nil || len(p) != maxPayload-size {
				t.Fatalf("empty UDP record: %d %v", len(p), err)
			}
		})
	}
	raw := &memoryConn{input: bytes.NewReader(nil)}
	_, pc := packetClient(t, raw)
	for _, dest := range []M.Socksaddr{{}, {Fqdn: strings.Repeat("a", 256), Port: 53}} {
		if err := pc.WritePacket(buf.As([]byte("x")), dest); err == nil {
			t.Fatal("accepted invalid address")
		}
	}
	c, _ := NewClient(ClientOptions{Version: 2, PSK: testPSK})
	if _, err := c.DialPacketConn(raw); err == nil || raw.output.Len() != 0 {
		t.Fatal("v2 UDP accepted")
	}
}

func responseWire(t *testing.T, packets [][]byte, combined bool) []byte {
	t.Helper()
	var wire bytes.Buffer
	w := recordWriter{upstream: &wire, psk: testPSK}
	if combined {
		w.writeRecord(append([]byte{0}, packets[0]...))
		packets = packets[1:]
	} else {
		w.writeRecord([]byte{0})
	}
	for _, p := range packets {
		if err := w.writeRecord(p); err != nil {
			t.Fatal(err)
		}
	}
	return wire.Bytes()
}

func TestUDPResponseFrames(t *testing.T) {
	cases := []struct{ address, source string }{
		{"04c00002010035", "192.0.2.1:53"},
		{"0620010db800000000000000000000000114e9", "[2001:db8::1]:5353"},
	}
	for _, tc := range cases {
		for _, combined := range []bool{false, true} {
			t.Run(tc.source+"/"+string(rune('0'+boolInt(combined))), func(t *testing.T) {
				header, _ := hex.DecodeString(tc.address)
				packets := [][]byte{append(append([]byte(nil), header...), []byte("one")...), append(append([]byte(nil), header...), []byte("two")...), header}
				raw := &memoryConn{input: bytes.NewReader(responseWire(t, packets, combined))}
				_, pc := packetClient(t, raw)
				for _, expected := range []string{"one", "two", ""} {
					b := buf.NewSize(20)
					source, err := pc.ReadPacket(b)
					if err != nil || source.String() != tc.source || string(b.Bytes()) != expected {
						t.Fatalf("source %s data %q err %v", source, b.Bytes(), err)
					}
					b.Release()
				}
			})
		}
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestUDPBadResponsesAndShortBuffer(t *testing.T) {
	for _, p := range [][]byte{{}, {3, 1, 'a', 0, 53}, {4, 1, 2}, {6, 1, 2, 3}, {7, 0, 0, 0, 0, 0, 0}} {
		raw := &memoryConn{input: bytes.NewReader(responseWire(t, [][]byte{p}, false))}
		_, pc := packetClient(t, raw)
		b := buf.NewSize(32)
		_, err := pc.ReadPacket(b)
		b.Release()
		if err == nil {
			t.Fatalf("accepted bad response %x", p)
		}
	}
	header := []byte{4, 192, 0, 2, 1, 0, 53}
	raw := &memoryConn{input: bytes.NewReader(responseWire(t, [][]byte{append(append([]byte(nil), header...), []byte("long")...), append(header, 'x')}, false))}
	_, pc := packetClient(t, raw)
	b := buf.NewSize(1)
	if _, err := pc.ReadPacket(b); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	if _, err := pc.ReadPacket(b); err != nil || string(b.Bytes()) != "x" {
		t.Fatalf("next datagram %q %v", b.Bytes(), err)
	}
	b.Release()
}
