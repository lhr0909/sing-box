// SPDX-License-Identifier: GPL-3.0-or-later
// Snell v3 UDP framing follows MetaCubeX/mihomo transport/snell (GPL-3.0),
// revision 0455d0d28c45. Responses contain IP addresses, never domain names.
package legacy

import (
	"errors"
	"io"
	"net"
	"sync"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func (c *Client) DialPacketConn(raw net.Conn) (N.NetPacketConn, error) {
	if c.options.Version != 3 {
		return nil, errors.New("snell: version 2 does not support UDP")
	}
	s, err := c.newSession(raw)
	if err != nil {
		return nil, err
	}
	return bufio.NewNetPacketConn(&packetConn{session: s}), nil
}

type packetConn struct {
	*session
	readMu    sync.Mutex
	writeMu   sync.Mutex
	requested bool
	replied   bool
	replyErr  error
}

// Called with writeMu held. Legacy UDP sends immediately, without waiting for
// a reply: some v3 servers wait for the first datagram before acknowledging.
func (c *packetConn) writeRequest() error {
	if c.requested {
		return c.writer.err
	}
	c.requested = true
	_, err := c.writer.Write([]byte{snell.RequestVersion, snell.CommandUDP, 0})
	return err
}

func (c *packetConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Validate and bound the entire datagram before writing any encrypted bytes.
	header := buf.NewSize(1 + 1 + 1 + 255 + 2)
	defer header.Release()
	header.WriteByte(snell.UDPCommandForward)
	if err := snell.WriteUDPRequestAddress(header, destination); err != nil {
		return err
	}
	if header.Len()+buffer.Len() > maxPayload {
		return snell.ErrPayloadTooLarge
	}
	if err := c.writeRequest(); err != nil {
		return err
	}
	packet := append(header.Bytes(), buffer.Bytes()...)
	return c.writer.writeRecord(packet)
}

func (c *packetConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.writeMu.Lock()
	err := c.writeRequest()
	c.writeMu.Unlock()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if !c.replied {
		// Legacy peers may combine the reply opcode and first UDP packet in one
		// record. Keep the remaining bytes in that record as exactly one datagram.
		c.replyErr = readReply(&c.reader)
		c.replied = true
	}
	if c.replyErr != nil {
		return M.Socksaddr{}, c.replyErr
	}
	packet := c.reader.pending
	c.reader.pending = nil
	if len(packet) == 0 {
		var err error
		packet, err = c.reader.readRecord()
		if errors.Is(err, errZeroChunk) {
			err = io.EOF
		}
		if err != nil {
			return M.Socksaddr{}, err
		}
	}
	record := buf.As(packet)
	source, err := snell.ReadUDPResponseAddress(record)
	if err != nil {
		return M.Socksaddr{}, err
	}
	if record.Len() > buffer.FreeLen() {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(record.Bytes())
	return source, err
}
