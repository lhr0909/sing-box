package legacy

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"
)

func TestIdlePoolBoundAndExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, err := NewClient(ClientOptions{Version: 2, PSK: testPSK})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		transports := make([]*memoryConn, 0, poolSize+1)
		for i := 0; i < poolSize+1; i++ {
			raw := &memoryConn{input: bytes.NewReader(nil)}
			transports = append(transports, raw)
			s, err := c.newSession(raw)
			if err != nil {
				t.Fatal(err)
			}
			c.put(s)
		}
		c.mu.Lock()
		idleCount := len(c.idle)
		c.mu.Unlock()
		if idleCount != poolSize || !transports[poolSize].closed {
			t.Fatal("pool exceeded idle limit")
		}
		time.Sleep(poolMaxIdle + time.Nanosecond)
		synctest.Wait()
		if len(c.idle) != 0 || len(c.sessions) != 0 {
			t.Fatal("expired sessions retained")
		}
		for _, raw := range transports {
			if !raw.closed {
				t.Fatal("expired transport left open")
			}
		}
	})
}

func TestBorrowedSessionOutlivesIdleTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c, err := NewClient(ClientOptions{Version: 2, PSK: testPSK})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		raw := &memoryConn{input: bytes.NewReader(nil)}
		s, err := c.newSession(raw)
		if err != nil {
			t.Fatal(err)
		}
		c.put(s)
		got, err := c.take()
		if err != nil || got != s {
			t.Fatalf("borrow: %v", err)
		}
		time.Sleep(poolMaxIdle + time.Nanosecond)
		synctest.Wait()
		if raw.closed {
			t.Fatal("idle timer closed borrowed transport")
		}
		c.SetKeepIdleConnections(false)
		c.put(s)
		if !raw.closed || len(c.idle) != 0 {
			t.Fatal("disabled idle retention kept transport")
		}
	})
}
