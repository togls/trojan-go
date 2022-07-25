package trojan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/togls/trojan-go/log"
)

const (
	MaxPacketSize = 1024 * 8
)

func relayUDP(ctx context.Context, conn net.Conn) (recv, send int64, err error) {
	errc := make(chan error)

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Error().Err(err).Msg("listen udp")
		return
	}
	defer udpConn.Close()

	go func() {
		for {
			n, playload, tgtAddr, err := readPacket(conn)
			if errors.Is(err, io.EOF) {
				errc <- nil
				return
			} else if err != nil {
				errc <- fmt.Errorf("read packet: %w", err)
				return
			}

			send += int64(n)

			_, err = udpConn.WriteToUDP(playload, tgtAddr)
			if err != nil {
				errc <- fmt.Errorf("write to udp: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			buf := make([]byte, MaxPacketSize)
			n, udpAddr, err := udpConn.ReadFromUDP(buf)
			if errors.Is(err, io.EOF) {
				errc <- nil
				return
			} else if err != nil {
				errc <- fmt.Errorf("read from udp: %w", err)
				return
			}

			recv += int64(n)

			addr := ParseAddr(udpAddr.String())

			err = writePacket(conn, buf[:n], addr)
			if err != nil {
				errc <- fmt.Errorf("write packet: %w", err)
				return
			}
		}
	}()

	select {
	case <-ctx.Done():
		return
	case err = <-errc:
		if err != nil {
			err = fmt.Errorf("udp relay: %w", err)
			return
		}
	}

	return
}

type packetConn struct {
	net.Conn
}

var _ net.PacketConn = (*packetConn)(nil)

func (pc *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	panic("not implemented")
}

func (pc *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	panic("not implemented")
}

func readPacket(r io.Reader) (int, []byte, *net.UDPAddr, error) {
	addr, err := ReadAddr(r)
	if err != nil {
		return 0, nil, nil, err
	}

	lengthBuf := make([]byte, 2)
	_, err = io.ReadFull(r, lengthBuf)
	if err != nil {
		return 0, nil, nil, err
	}

	length := int(binary.BigEndian.Uint16(lengthBuf))

	// crlf
	crlf := make([]byte, 2)
	_, err = io.ReadFull(r, crlf[:])
	if err != nil {
		return 0, nil, nil, err
	}

	playload := make([]byte, length)
	_, err = io.ReadFull(r, playload)
	if err != nil {
		return 0, nil, nil, err
	}

	return length, playload, addr.ToUDPAddr(), nil
}

func writePacket(w io.Writer, playload []byte, addr Addr) error {
	_, err := w.Write(addr)
	if err != nil {
		return err
	}

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(playload)))
	_, err = w.Write(length)
	if err != nil {
		return err
	}

	// crlf
	crlf := [...]byte{'\r', '\n'}
	_, err = w.Write(crlf[:])
	if err != nil {
		return err
	}

	_, err = w.Write(playload)
	if err != nil {
		return err
	}

	return nil
}
