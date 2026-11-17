// SPDX-License-Identifier: GPL-3.0-or-later
// Protocol and conservative reuse lifecycle adapted from MetaCubeX/mihomo
// transport/snell (GPL-3.0), revision 0455d0d28c45.
package legacy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	poolSize    = 10
	poolMaxIdle = 15 * time.Second
)

type ClientOptions struct {
	Version int
	PSK     []byte
	Obfs    snell.ObfsConfig
	Dialer  N.Dialer
	Server  M.Socksaddr
}

type Client struct {
	options    ClientOptions
	mu         sync.Mutex
	closed     bool
	keepIdle   bool
	generation uint64
	idle       []*session
	sessions   map[*session]struct{}
}

func NewClient(options ClientOptions) (*Client, error) {
	if options.Version != 2 && options.Version != 3 {
		return nil, errors.New("snell: unsupported legacy version")
	}
	if len(options.PSK) == 0 {
		return nil, snell.ErrMissingPSK
	}
	switch options.Obfs.Mode {
	case snell.ObfsModeNone, snell.ObfsModeHTTP, snell.ObfsModeTLS:
	default:
		return nil, errors.New("snell: unknown obfs mode")
	}
	options.PSK = append([]byte(nil), options.PSK...)
	return &Client{options: options, keepIdle: true, sessions: make(map[*session]struct{})}, nil
}

type session struct {
	net.Conn
	raw        net.Conn
	client     *Client
	generation uint64
	reader     recordReader
	writer     recordWriter
	timer      *time.Timer // guarded by client.mu
	timerEpoch uint64
	closeOnce  sync.Once
	closeErr   error
}

func (s *session) Close() error {
	s.closeOnce.Do(func() {
		c := s.client
		c.mu.Lock()
		delete(c.sessions, s)
		c.removeIdle(s)
		if s.timer != nil {
			s.timer.Stop()
		}
		c.mu.Unlock()
		s.closeErr = s.Conn.Close()
	})
	return s.closeErr
}

func (c *Client) newSession(raw net.Conn) (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		raw.Close()
		return nil, net.ErrClosed
	}
	conn := c.options.Obfs.ClientConn(raw)
	s := &session{Conn: conn, raw: raw, client: c, generation: c.generation,
		reader: recordReader{upstream: conn, psk: c.options.PSK},
		writer: recordWriter{upstream: conn, psk: c.options.PSK}}
	c.sessions[s] = struct{}{}
	return s, nil
}

func (c *Client) removeIdle(s *session) {
	for i, entry := range c.idle {
		if entry == s {
			c.idle = append(c.idle[:i], c.idle[i+1:]...)
			return
		}
	}
}

func (c *Client) take() (*session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	if len(c.idle) == 0 {
		return nil, nil
	}
	i := len(c.idle) - 1
	s := c.idle[i]
	c.idle = c.idle[:i]
	s.timer.Stop()
	s.timer = nil
	s.timerEpoch++
	return s, nil
}

func (c *Client) put(s *session) {
	c.mu.Lock()
	_, alive := c.sessions[s]
	if !alive || c.closed || !c.keepIdle || s.generation != c.generation || len(c.idle) >= poolSize {
		c.mu.Unlock()
		s.Close()
		return
	}
	c.idle = append(c.idle, s)
	s.timerEpoch++
	epoch := s.timerEpoch
	s.timer = time.AfterFunc(poolMaxIdle, func() {
		c.mu.Lock()
		// A stopped timer may already be running. Only expire its own idle entry.
		idle := false
		for _, entry := range c.idle {
			if entry == s && s.timerEpoch == epoch {
				idle = true
				break
			}
		}
		if idle {
			c.removeIdle(s)
		}
		c.mu.Unlock()
		if idle {
			s.Close()
		}
	})
	c.mu.Unlock()
}

func (c *Client) DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := c.take()
	if err != nil {
		return nil, err
	}
	if s == nil {
		if c.options.Dialer == nil {
			return nil, errors.New("snell: missing dialer")
		}
		raw, dialErr := c.options.Dialer.DialContext(ctx, N.NetworkTCP, c.options.Server)
		if dialErr != nil {
			return nil, dialErr
		}
		s, err = c.newSession(raw)
		if err != nil {
			return nil, err
		}
	}
	// Cancellation must also interrupt an obfuscated request blocked in Write.
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	conn := &streamConn{session: s, reuse: c.options.Version == 2}
	command := byte(snell.CommandConnect)
	if conn.reuse {
		command = snell.CommandConnectV2
	}
	request := snell.Request{Command: command, Destination: destination}
	buffer := buf.NewSize(request.Len())
	defer buffer.Release()
	err = request.Write(buffer)
	if err == nil {
		_, err = s.writer.Write(buffer.Bytes())
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		s.Close()
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return nil, err
	}
	return conn, nil
}

func (c *Client) Reset() { c.CloseIdleConnections() }

func (c *Client) SetKeepIdleConnections(keep bool) {
	c.mu.Lock()
	c.keepIdle = keep
	c.mu.Unlock()
	if !keep {
		c.CloseIdleConnections()
	}
}

func (c *Client) CloseIdleConnections() {
	c.mu.Lock()
	c.generation++ // Active requests from the previous network must not reenter.
	idle := c.idle
	c.idle = nil
	c.mu.Unlock()
	for _, s := range idle {
		s.Close()
	}
}

func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	sessions := make([]*session, 0, len(c.sessions))
	for s := range c.sessions {
		sessions = append(sessions, s)
	}
	c.mu.Unlock()
	var err error
	for _, s := range sessions {
		err = errors.Join(err, s.Close())
	}
	return err
}

type streamConn struct {
	*session
	reuse         bool
	readMu        sync.Mutex
	writeMu       sync.Mutex
	deadlineMu    sync.Mutex
	replied       bool
	replyErr      error
	peerClosed    atomic.Bool
	failed        atomic.Bool
	closed        atomic.Bool
	writeClosed   bool
	writeCloseErr error
	closeOnce     sync.Once
	closeErr      error
}

func readReply(reader io.Reader) error {
	var prefix [1]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return err
	}
	switch prefix[0] {
	case snell.ReplyTunnel:
		return nil
	case snell.ReplyError:
		var header [2]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return err
		}
		message := make([]byte, int(header[1]))
		if _, err := io.ReadFull(reader, message); err != nil {
			return err
		}
		return fmt.Errorf("snell: server error %d: %s", header[0], message)
	default:
		return fmt.Errorf("snell: unexpected reply opcode: %d", prefix[0])
	}
}

func (c *streamConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.peerClosed.Load() {
		return 0, io.EOF
	}
	if !c.replied {
		c.replyErr = readReply(&c.reader)
		c.replied = true
	}
	if c.replyErr != nil {
		c.failed.Store(true)
		return 0, c.replyErr
	}
	n, err := c.reader.Read(p)
	if errors.Is(err, errZeroChunk) {
		c.peerClosed.Store(true)
		return n, io.EOF
	}
	if err != nil {
		c.failed.Store(true)
	}
	return n, err
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() || c.writeClosed {
		return 0, net.ErrClosed
	}
	n, err := c.writer.Write(p)
	if err != nil {
		c.failed.Store(true)
	}
	return n, err
}

func (c *streamConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return c.writeCloseErr
	}
	c.writeClosed = true
	if c.reuse {
		c.writeCloseErr = c.writer.writeRecord(nil)
	} else {
		c.writeCloseErr = N.CloseWrite(c.raw)
	}
	if c.writeCloseErr != nil {
		c.failed.Store(true)
	}
	return c.writeCloseErr
}

func (c *streamConn) Close() error {
	c.closeOnce.Do(func() {
		c.deadlineMu.Lock()
		defer c.deadlineMu.Unlock()
		c.closed.Store(true)
		// Never wait for an unread response while closing. Unread/failed streams are
		// discarded, so the next user cannot inherit buffered bytes or a server error.
		if !c.reuse || !c.peerClosed.Load() || c.failed.Load() {
			c.closeErr = c.session.Close()
			return
		}
		c.closeErr = c.CloseWrite()
		if c.closeErr == nil {
			c.closeErr = c.Conn.SetDeadline(time.Time{})
		}
		if c.closeErr != nil {
			c.session.Close()
			return
		}
		c.client.put(c.session)
	})
	return c.closeErr
}

func (c *streamConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Conn.SetDeadline(deadline)
}

func (c *streamConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *streamConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Conn.SetWriteDeadline(deadline)
}
