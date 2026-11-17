package legacy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	M "github.com/sagernet/sing/common/metadata"
)

type pipeDialer struct {
	count   atomic.Int32
	serve   func(net.Conn) error
	results chan error
}

func (d *pipeDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	a, b := net.Pipe()
	a.SetDeadline(time.Now().Add(3 * time.Second))
	b.SetDeadline(time.Now().Add(3 * time.Second))
	d.count.Add(1)
	go func() { defer b.Close(); d.results <- d.serve(b) }()
	return a, nil
}
func (d *pipeDialer) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func newTestClient(t *testing.T, version int, serve func(net.Conn) error) (*Client, *pipeDialer) {
	t.Helper()
	d := &pipeDialer{serve: serve, results: make(chan error, 32)}
	c, err := NewClient(ClientOptions{Version: version, PSK: testPSK, Dialer: d})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, d
}

func echoRequests(raw net.Conn, version, count int, halfClose bool) error {
	r := recordReader{upstream: raw, psk: testPSK}
	w := recordWriter{upstream: raw, psk: testPSK}
	for i := 0; i < count; i++ {
		req, err := snell.ReadRequest(&r)
		if err != nil {
			return err
		}
		expected := byte(snell.CommandConnect)
		if version == 2 {
			expected = snell.CommandConnectV2
		}
		if req.Command != expected || req.Destination.String() != "example.com:443" || len(req.ClientID) != 0 {
			return fmt.Errorf("request: %+v", req)
		}
		p := make([]byte, 5)
		if _, err = io.ReadFull(&r, p); err != nil {
			return err
		}
		if string(p) != "hello" {
			return fmt.Errorf("payload: %q", p)
		}
		if halfClose {
			if _, err = r.Read(p[:1]); !errors.Is(err, errZeroChunk) {
				return fmt.Errorf("client EOF: %v", err)
			}
		}
		if _, err = w.Write(append([]byte{snell.ReplyTunnel}, p...)); err != nil {
			return err
		}
		if version == 2 {
			if err = w.writeRecord(nil); err != nil {
				return err
			}
			if !halfClose {
				if _, err = r.Read(p[:1]); !errors.Is(err, errZeroChunk) {
					return fmt.Errorf("client EOF: %v", err)
				}
			}
		}
	}
	return nil
}

func TestV2ReuseAndHalfClose(t *testing.T) {
	for _, halfClose := range []bool{false, true} {
		t.Run(fmt.Sprint(halfClose), func(t *testing.T) {
			done := make(chan struct{})
			results := make(chan error, 1)
			defer close(done)
			c, d := newTestClient(t, 2, func(raw net.Conn) error {
				err := echoRequests(raw, 2, 2, halfClose)
				results <- err
				<-done
				return err
			})
			for i := 0; i < 2; i++ {
				conn, err := c.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = conn.Write([]byte("hello")); err != nil {
					t.Fatal(err)
				}
				if halfClose {
					if err = conn.(*streamConn).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if err = conn.(*streamConn).CloseWrite(); err != nil {
						t.Fatal(err)
					}
					if _, err = conn.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
						t.Fatal(err)
					}
				}
				p, err := io.ReadAll(conn)
				if err != nil || string(p) != "hello" {
					t.Fatalf("reply: %q %v", p, err)
				}
				conn.SetReadDeadline(time.Now().Add(-time.Second))
				if err = conn.Close(); err != nil {
					t.Fatal(err)
				}
				if err = conn.Close(); err != nil {
					t.Fatal(err)
				}
				if err = conn.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
				if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			}
			if d.count.Load() != 1 {
				t.Fatalf("dials=%d, want 1", d.count.Load())
			}
			if err := <-results; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV3TCP(t *testing.T) {
	c, d := newTestClient(t, 3, func(raw net.Conn) error { return echoRequests(raw, 3, 1, false) })
	conn, err := c.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("hello"))
	p, err := io.ReadAll(conn)
	if err != nil || string(p) != "hello" {
		t.Fatalf("reply: %q %v", p, err)
	}
	conn.Close()
	if err = <-d.results; err != nil {
		t.Fatal(err)
	}
}

func TestReuseCleanup(t *testing.T) {
	for _, action := range []string{"reset-idle", "reset-active", "disable-idle", "close-idle", "close-client"} {
		t.Run(action, func(t *testing.T) {
			c, d := newTestClient(t, 2, func(raw net.Conn) error { return echoRequests(raw, 2, 1, false) })
			conn, err := c.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
			if err != nil {
				t.Fatal(err)
			}
			conn.Write([]byte("hello"))
			io.ReadAll(conn)
			if action == "reset-active" {
				c.Reset()
			}
			conn.Close()
			switch action {
			case "reset-idle":
				c.Reset()
			case "disable-idle":
				c.SetKeepIdleConnections(false)
			case "close-idle":
				c.CloseIdleConnections()
			case "close-client":
				c.Close()
			}
			c.mu.Lock()
			n := len(c.idle)
			c.mu.Unlock()
			if n != 0 {
				t.Fatalf("%d idle sessions", n)
			}
			if err = <-d.results; err != nil {
				t.Fatal(err)
			}
			if action == "close-client" {
				if _, err = c.DialContext(context.Background(), M.ParseSocksaddr("example.com:443")); !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestUnreadAndErrorStreamsNeverReused(t *testing.T) {
	for _, reply := range [][]byte{nil, {2, 6, 7, 'r', 'e', 'f', 'u', 's', 'e', 'd'}, {9}} {
		t.Run(fmt.Sprintf("%x", reply), func(t *testing.T) {
			c, _ := newTestClient(t, 2, func(raw net.Conn) error {
				r := recordReader{upstream: raw, psk: testPSK}
				if _, err := snell.ReadRequest(&r); err != nil {
					return err
				}
				if reply != nil {
					w := recordWriter{upstream: raw, psk: testPSK}
					_, err := w.Write(reply)
					return err
				}
				_, err := raw.Read(make([]byte, 1))
				return err
			})
			conn, err := c.DialContext(context.Background(), M.ParseSocksaddr("example.com:443"))
			if err != nil {
				t.Fatal(err)
			}
			if reply != nil {
				_, err = conn.Read(make([]byte, 1))
				if err == nil {
					t.Fatal("accepted error reply")
				}
				_, again := conn.Read(make([]byte, 1))
				if again == nil || again.Error() != err.Error() {
					t.Fatal("reply error not sticky")
				}
			}
			conn.Close()
			c.mu.Lock()
			n := len(c.idle)
			c.mu.Unlock()
			if n != 0 {
				t.Fatal("pooled unread/error stream")
			}
		})
	}
}

func TestReplyErrors(t *testing.T) {
	for _, p := range [][]byte{{}, {1}, {2}, {2, 5}, {2, 5, 9, 'a'}} {
		if err := readReply(bytes.NewReader(p)); err == nil {
			t.Fatalf("accepted %x", p)
		}
	}
	err := readReply(bytes.NewReader([]byte{2, 6, 7, 'r', 'e', 'f', 'u', 's', 'e', 'd'}))
	if err == nil || !strings.Contains(err.Error(), "6: refused") {
		t.Fatal(err)
	}
}

func TestDialCancellationAndBadDestination(t *testing.T) {
	c, d := newTestClient(t, 2, func(raw net.Conn) error { _, err := raw.Read(make([]byte, 1)); return err })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.DialContext(ctx, M.ParseSocksaddr("example.com:443")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if d.count.Load() != 0 {
		t.Fatal("dialed canceled context")
	}
	if _, err := c.DialContext(context.Background(), M.Socksaddr{Fqdn: strings.Repeat("x", 256), Port: 443}); err == nil {
		t.Fatal("accepted long hostname")
	}
	// A peer that never reads must not trap a canceled header write.
	c2, _ := newTestClient(t, 2, func(raw net.Conn) error { time.Sleep(300 * time.Millisecond); return nil })
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := c2.DialContext(ctx, M.ParseSocksaddr("example.com:443")); err == nil {
		t.Fatal("expected cancellation")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel did not interrupt handshake")
	}
}
