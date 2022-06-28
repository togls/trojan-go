package trojan

import (
	"errors"
	"net"
)

type listner struct {
	net.Listener

	conn chan net.Conn
	done chan struct{}
}

func (ln *listner) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-ln.conn:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return conn, nil
	case <-ln.done:
		return nil, errors.New("sever closed")
	}
}

func (ln *listner) Close() error {
	select {
	case <-ln.done:
	default:
		close(ln.done)
	}

	return ln.Listener.Close()
}
