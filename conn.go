package trojan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
)

type bufConn struct {
	net.Conn

	user []byte
	addr Addr
	cmd  Command

	buff bufferedReader
}

func newBufConn(conn net.Conn) *bufConn {
	return &bufConn{
		Conn: conn,

		buff: bufferedReader{
			reader: conn,
		},
	}
}

func (conn *bufConn) Read(b []byte) (int, error) {
	return conn.buff.Read(b)
}

func (conn *bufConn) startBuffing() {
	conn.buff.reset(true)
}

func (conn *bufConn) stopBuffing() {
	conn.buff.reset(false)
}

func (conn *bufConn) Auth(authenticator Authenticator) error {
	conn.startBuffing()
	defer conn.stopBuffing()

	var pw [56]byte
	_, err := io.ReadFull(conn, pw[:])
	if err != nil {
		return fmt.Errorf("read password, %w", err)
	}

	user, ok := authenticator.Auth(pw[:])
	if !ok {
		return errors.New("password not match")
	}
	conn.user = user

	var crlf [2]byte
	var cmd [1]byte

	// crlf
	_, err = io.ReadFull(conn, crlf[:])
	if err != nil {
		return fmt.Errorf("read crlf, %w", err)
	}

	// cmd
	_, err = io.ReadFull(conn, cmd[:])
	if err != nil {
		return fmt.Errorf("read command, %w", err)
	}
	conn.cmd = Command(cmd[0])

	// dst addr and port
	addr, err := ReadAddr(conn)
	if err != nil {
		return fmt.Errorf("read address, %w", err)
	}
	conn.addr = addr

	// crlf
	_, err = io.ReadFull(conn, crlf[:])
	if err != nil {
		return fmt.Errorf("read crlf, %w", err)
	}

	return nil
}

type bufferedReader struct {
	reader io.Reader

	size   int
	buffer bytes.Buffer

	buffing bool
	read    int
	lastErr error
}

func (buf *bufferedReader) Read(b []byte) (int, error) {
	if buf.size > buf.read {
		n := copy(b, buf.buffer.Bytes()[buf.read:buf.size])
		buf.read += n
		return n, buf.lastErr
	} else if !buf.buffing && buf.buffer.Cap() > 0 {
		buf.buffer = bytes.Buffer{}
	}

	n, err := buf.reader.Read(b)
	if buf.buffing && n > 0 {
		buf.lastErr = err
		if n, err := buf.buffer.Write(b[:n]); err != nil {
			return n, err
		}
	}
	return n, err
}

func (buf *bufferedReader) reset(buffing bool) {
	buf.buffing = buffing
	buf.read = 0
	buf.size = buf.buffer.Len()
}
