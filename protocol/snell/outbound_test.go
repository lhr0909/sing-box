package snell

import (
	"context"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func testOptions(version int) option.SnellOutboundOptions {
	return option.SnellOutboundOptions{Version: version, AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
		ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: 10000}, PSK: "local-test-password",
	}}
}

func TestOutboundVersionValidation(t *testing.T) {
	for _, version := range []int{2, 3, 4, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", testOptions(version))
			if err != nil {
				t.Fatal(err)
			}
			h := out.(*Outbound)
			defer h.client.Close()
			if slices.Contains(h.Network(), N.NetworkUDP) != (version != 2) {
				t.Fatalf("networks %v", h.Network())
			}
			if h.MultiplexEnabled() != (version == 2) {
				t.Fatalf("reuse: %v", h.MultiplexEnabled())
			}
			if version == 2 {
				if _, err = h.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:53")); err == nil {
					t.Fatal("v2 ListenPacket accepted")
				}
				if _, err = h.DialContext(context.Background(), N.NetworkUDP, M.ParseSocksaddr("127.0.0.1:53")); err == nil {
					t.Fatal("v2 UDP dial accepted")
				}
			}
		})
	}
	for _, tc := range []struct {
		name    string
		options option.SnellOutboundOptions
		want    string
	}{
		{"v2 UDP", func() option.SnellOutboundOptions { o := testOptions(2); o.Network = "udp"; return o }(), "does not support UDP"},
		{"v2 both", func() option.SnellOutboundOptions { o := testOptions(2); o.Network = "tcp\nudp"; return o }(), "does not support UDP"},
		{"v3 reuse", func() option.SnellOutboundOptions { o := testOptions(3); o.Reuse = true; return o }(), "does not support connection reuse"},
		{"v2 user", func() option.SnellOutboundOptions { o := testOptions(2); o.UserKey = "user"; return o }(), "userkey"},
		{"v3 user", func() option.SnellOutboundOptions { o := testOptions(3); o.UserKey = "user"; return o }(), "userkey"},
		{"no PSK", func() option.SnellOutboundOptions { o := testOptions(3); o.PSK = ""; return o }(), "pre-shared key"},
		{"bad obfs", func() option.SnellOutboundOptions { o := testOptions(3); o.ObfsOptions.ObfsMode = "unknown"; return o }(), "obfs"},
		{"missing version", testOptions(0), "missing version"},
		{"unsupported version", testOptions(5), "unsupported version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", tc.options)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want %q", err, tc.want)
			}
		})
	}
}

type echoHandler struct{}

func (echoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		io.Copy(conn, conn)
		if onClose != nil {
			onClose(nil)
		}
	}()
}
func (echoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		defer conn.Close()
		for {
			buffer := buf.NewPacket()
			buffer.Resize(N.CalculateFrontHeadroom(conn), 0)
			destination, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				return
			}
			if err = conn.WritePacket(buffer, destination); err != nil {
				return
			}
		}
	}()
}

func TestV4V6TCPRegression(t *testing.T) {
	for _, version := range []int{4, 6} {
		for _, reuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("v%d/reuse=%v", version, reuse), func(t *testing.T) {
				options := testOptions(version)
				options.Reuse = reuse
				var service snellprotocol.Service
				var err error
				if version == 4 {
					service, err = snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(options.PSK), Handler: echoHandler{}})
				} else {
					service, err = snellv6.NewService(snellv6.ServerOptions{PSK: []byte(options.PSK), Handler: echoHandler{}})
				}
				if err != nil {
					t.Fatal(err)
				}
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				go func() {
					for {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						go func() {
							if err := service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil); err != nil {
								conn.Close()
							}
						}()
					}
				}()
				options.ServerPort = M.SocksaddrFromNet(ln.Addr()).Port
				out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", options)
				if err != nil {
					t.Fatal(err)
				}
				h := out.(*Outbound)
				defer h.client.Close()
				conn, err := h.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddr("example.com:443"))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				payload := strings.Repeat("existing version regression ", 1000)
				if _, err = conn.Write([]byte(payload)); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err = io.ReadFull(conn, got); err != nil || string(got) != payload {
					t.Fatalf("echo: %v", err)
				}
			})
		}
	}
}

func TestV4V6UDPRegression(t *testing.T) {
	for _, version := range []int{4, 6} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			options := testOptions(version)
			var service snellprotocol.Service
			var err error
			if version == 4 {
				service, err = snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(options.PSK), Handler: echoHandler{}})
			} else {
				service, err = snellv6.NewService(snellv6.ServerOptions{PSK: []byte(options.PSK), Handler: echoHandler{}})
			}
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				if err = service.NewConnection(context.Background(), conn, M.SocksaddrFromNet(conn.RemoteAddr()), nil); err != nil {
					conn.Close()
				}
			}()
			options.ServerPort = M.SocksaddrFromNet(ln.Addr()).Port
			out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().Logger(), "test", options)
			if err != nil {
				t.Fatal(err)
			}
			h := out.(*Outbound)
			defer h.client.Close()
			destination := M.ParseSocksaddr("127.0.0.1:53")
			pc, err := h.ListenPacket(context.Background(), destination)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			pc.SetDeadline(time.Now().Add(3 * time.Second))
			payload := []byte("existing UDP regression")
			if _, err = pc.WriteTo(payload, destination.UDPAddr()); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 100)
			n, source, err := pc.ReadFrom(got)
			if err != nil || string(got[:n]) != string(payload) || source.String() != destination.String() {
				t.Fatalf("UDP source %v payload %q err %v", source, got[:n], err)
			}
		})
	}
}
